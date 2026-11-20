use sea_orm::{ConnectionTrait, TransactionTrait};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let tx = manager.get_connection().begin().await?;
        // Use one transaction for the identity-preserving copy and the composite constraints.
        tx.execute_unprepared(
            r#"
            LOCK TABLE vlan_network, vlan_gateway, vlan_grant, vlan_route IN ACCESS EXCLUSIVE MODE;
            ALTER TABLE vlan_grant ADD UNIQUE (creator, vlan_id, supplicant_id);
            CREATE TABLE vlan_tunnel (
                id uuid PRIMARY KEY DEFAULT uuidv7(),
                creator varchar NOT NULL,
                vlan_id uuid NOT NULL,
                name text NOT NULL,
                kind text NOT NULL,
                server text,
                port integer CHECK (port BETWEEN 1 AND 65535),
                subnet cidr,
                private_key text,
                allowed_ips text[] NOT NULL,
                UNIQUE (vlan_id, name),
                UNIQUE (creator, vlan_id, id, kind),
                UNIQUE (vlan_id, subnet),
                FOREIGN KEY (creator, vlan_id) REFERENCES vlan_network (creator, id) ON DELETE CASCADE,
                CHECK (
                    (kind = 'easytier-gateway' AND server IS NOT NULL AND port IS NOT NULL
                        AND subnet IS NOT NULL AND private_key IS NOT NULL AND cardinality(allowed_ips) > 0)
                    OR (kind = 'wireguard-compatible' AND server IS NULL AND port IS NULL
                        AND subnet IS NULL AND private_key IS NULL AND cardinality(allowed_ips) = 0)
                )
            );
            CREATE TABLE vlan_tunnel_grant (
                id uuid PRIMARY KEY DEFAULT uuidv7(),
                creator varchar NOT NULL,
                vlan_id uuid NOT NULL,
                tunnel_id uuid NOT NULL,
                kind text NOT NULL,
                supplicant_id uuid NOT NULL,
                slots text,
                addresses text[] NOT NULL,
                mtu integer CHECK (mtu BETWEEN 1 AND 65535),
                persistent_keepalive integer CHECK (persistent_keepalive BETWEEN 0 AND 65535),
                private_key text,
                UNIQUE (tunnel_id, supplicant_id),
                UNIQUE (id, kind),
                FOREIGN KEY (creator, vlan_id, tunnel_id, kind)
                    REFERENCES vlan_tunnel (creator, vlan_id, id, kind) ON DELETE CASCADE,
                FOREIGN KEY (creator, vlan_id, supplicant_id)
                    REFERENCES vlan_grant (creator, vlan_id, supplicant_id) ON DELETE CASCADE,
                CHECK (
                    (kind = 'easytier-gateway' AND slots IS NOT NULL AND cardinality(addresses) = 0
                        AND private_key IS NULL AND mtu IS NULL AND persistent_keepalive IS NULL)
                    OR (kind = 'wireguard-compatible' AND slots IS NULL AND cardinality(addresses) > 0
                        AND private_key IS NOT NULL)
                )
            );
            CREATE INDEX vlan_tunnel_grant_membership_idx
                ON vlan_tunnel_grant (creator, vlan_id, supplicant_id);
            CREATE TABLE vlan_wireguard_peer (
                id uuid PRIMARY KEY DEFAULT uuidv7(),
                grant_id uuid NOT NULL,
                kind text GENERATED ALWAYS AS ('wireguard-compatible') STORED,
                position integer NOT NULL,
                server text NOT NULL,
                port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
                public_key text NOT NULL,
                pre_shared_key text,
                allowed_ips text[] NOT NULL CHECK (cardinality(allowed_ips) > 0),
                UNIQUE (grant_id, position),
                UNIQUE (grant_id, public_key),
                FOREIGN KEY (grant_id, kind)
                    REFERENCES vlan_tunnel_grant (id, kind) ON DELETE CASCADE
            );

            INSERT INTO vlan_route (vlan_id, cidr)
            SELECT vlan_id, subnet FROM vlan_gateway
            ON CONFLICT (vlan_id, cidr) DO NOTHING;

            INSERT INTO vlan_tunnel (id, creator, vlan_id, name, kind, server, port, subnet, private_key, allowed_ips)
            SELECT g.id, v.creator, g.vlan_id, g.name, 'easytier-gateway',
                g.server, g.port, g.subnet, g.private_key,
                ARRAY(SELECT host(r.cidr) || '/' || masklen(r.cidr)
                    FROM vlan_route r WHERE r.vlan_id = g.vlan_id ORDER BY r.cidr)
            FROM vlan_gateway g JOIN vlan_network v ON v.id = g.vlan_id;

            INSERT INTO vlan_tunnel_grant (creator, vlan_id, tunnel_id, kind, supplicant_id, slots, addresses)
            SELECT t.creator, t.vlan_id, t.id, t.kind, g.supplicant_id, g.slots, '{}'::text[]
            FROM vlan_tunnel t JOIN vlan_grant g ON (g.creator, g.vlan_id) = (t.creator, t.vlan_id);

            ALTER TABLE vlan_grant DROP COLUMN slots;
            DROP TABLE vlan_gateway;
            "#,
        )
        .await?;
        tx.commit().await
    }

    async fn down(&self, _: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "Restore the pre-migration backup to return to VLAN-level slot grants".into(),
        ))
    }
}

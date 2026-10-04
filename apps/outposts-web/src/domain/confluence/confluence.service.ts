import { HttpClient } from "@angular/common/http";
import { Injectable, inject } from "@angular/core";
import { environment } from "@/environments/environment";
import type { ConfluenceDto } from "./bindings/ConfluenceDto";
import type { ConfluenceUpdateCronDto } from "./bindings/ConfluenceUpdateCronDto";
import type { ConfluenceUpdateDto } from "./bindings/ConfluenceUpdateDto";
import type { ProfileCreationDto } from "./bindings/ProfileCreationDto";
import type { ProfileDto } from "./bindings/ProfileDto";
import type { ProfileUpdateDto } from "./bindings/ProfileUpdateDto";
import type { SubscribeSourceCreationDto } from "./bindings/SubscribeSourceCreationDto";
import type { SubscribeSourceDto } from "./bindings/SubscribeSourceDto";
import type { SubscribeSourceUpdateDto } from "./bindings/SubscribeSourceUpdateDto";
import type { UUIDV7 } from "./bindings/UUIDV7";
import type { VlanConfig } from "./bindings/VlanConfig";
import type { VlanNetwork } from "./bindings/VlanNetwork";
import type { VlanSupplicant } from "./bindings/VlanSupplicant";
import type { WorkspaceVlansUpdateDto } from "./bindings/WorkspaceVlansUpdateDto";

@Injectable()
export class ConfluenceService {
  protected readonly apiEndpoint = environment.CONFLUENCE_API_ENDPOINT;
  protected httpClient: HttpClient = inject(HttpClient);

  getAllConfluences() {
    return this.httpClient.get<ConfluenceDto[]>(
      `${environment.CONFLUENCE_API_ENDPOINT}/confluence`,
      {
        responseType: "json",
      },
    );
  }

  addConfluence() {
    return this.httpClient.post<ConfluenceDto>(
      `${environment.CONFLUENCE_API_ENDPOINT}/confluence`,
      {},
      {
        responseType: "json",
      },
    );
  }

  removeConfluence(id: string) {
    return this.httpClient.delete(`${environment.CONFLUENCE_API_ENDPOINT}/confluence/${id}`, {
      responseType: "json",
    });
  }

  getConfluenceById(id: string) {
    return this.httpClient.get<ConfluenceDto>(
      `${environment.CONFLUENCE_API_ENDPOINT}/confluence/${id}`,
      {
        responseType: "json",
      },
    );
  }

  updateConfluence(id: string, form: ConfluenceUpdateDto) {
    return this.httpClient.put<ConfluenceDto>(
      `${environment.CONFLUENCE_API_ENDPOINT}/confluence/${id}`,
      form,
      {
        responseType: "json",
      },
    );
  }

  getVlanCatalog() {
    return this.httpClient.get<VlanConfig>(`${this.apiEndpoint}/vlan`);
  }

  aggregateVlanRoutes(routes: string[]) {
    return this.httpClient.post<string[]>(`${this.apiEndpoint}/vlan/routes/aggregate`, routes);
  }

  saveVlan(network: VlanNetwork) {
    const url = `${this.apiEndpoint}/vlan`;
    return network.id
      ? this.httpClient.put<VlanNetwork>(`${url}/${network.id}`, network)
      : this.httpClient.post<VlanNetwork>(url, network);
  }

  removeVlan(id: string) {
    return this.httpClient.delete<void>(`${this.apiEndpoint}/vlan/${id}`);
  }

  saveSupplicant(supplicant: VlanSupplicant) {
    const url = `${this.apiEndpoint}/vlan/supplicants`;
    return supplicant.id
      ? this.httpClient.put<VlanSupplicant>(`${url}/${supplicant.id}`, supplicant)
      : this.httpClient.post<VlanSupplicant>(url, supplicant);
  }

  removeSupplicant(id: string) {
    return this.httpClient.delete<void>(`${this.apiEndpoint}/vlan/supplicants/${id}`);
  }

  updateWorkspaceVlans(id: UUIDV7, input: WorkspaceVlansUpdateDto) {
    return this.httpClient.put<UUIDV7[]>(`${this.apiEndpoint}/confluence/${id}/vlans`, input);
  }

  addSubscribeSource(form: SubscribeSourceCreationDto) {
    return this.httpClient.post<SubscribeSourceDto>(
      `${environment.CONFLUENCE_API_ENDPOINT}/subscribe_source`,
      form,
      {
        responseType: "json",
      },
    );
  }

  removeSubscribeSource(id: string) {
    return this.httpClient.delete(`${environment.CONFLUENCE_API_ENDPOINT}/subscribe_source/${id}`, {
      responseType: "json",
    });
  }

  updateSubscribeSource(id: string, form: SubscribeSourceUpdateDto) {
    return this.httpClient.put<SubscribeSourceDto>(
      `${environment.CONFLUENCE_API_ENDPOINT}/subscribe_source/${id}`,
      form,
      {
        responseType: "json",
      },
    );
  }

  syncConfluence(id: string) {
    return this.httpClient.post<ConfluenceDto>(
      `${environment.CONFLUENCE_API_ENDPOINT}/confluence/sync/${id}`,
      {},
      {
        responseType: "json",
      },
    );
  }

  syncSubscribeSource(id: string) {
    return this.httpClient.post<SubscribeSourceDto>(
      `${environment.CONFLUENCE_API_ENDPOINT}/subscribe_source/sync/${id}`,
      {},
      {
        responseType: "json",
      },
    );
  }

  muxConfluence(id: string) {
    return this.httpClient.post<ConfluenceDto>(
      `${environment.CONFLUENCE_API_ENDPOINT}/confluence/mux/${id}`,
      {},
      {
        responseType: "json",
      },
    );
  }

  addProfile(form: ProfileCreationDto) {
    return this.httpClient.post<ProfileDto>(
      `${environment.CONFLUENCE_API_ENDPOINT}/profile`,
      form,
      {
        responseType: "json",
      },
    );
  }

  removeProfile(id: string) {
    return this.httpClient.delete(`${environment.CONFLUENCE_API_ENDPOINT}/profile/${id}`, {
      responseType: "json",
    });
  }

  updateProfile(id: string, form: ProfileUpdateDto) {
    return this.httpClient.put<ProfileDto>(
      `${environment.CONFLUENCE_API_ENDPOINT}/profile/${id}`,
      form,
      {
        responseType: "json",
      },
    );
  }

  getProfileUrl(resourceToken: ProfileDto["resource_token"]) {
    return `${environment.CONFLUENCE_API_ENDPOINT}/profile_token/${resourceToken}`;
  }

  updateConfluenceCron(confluenceId: string, updateCronDto: ConfluenceUpdateCronDto) {
    return this.httpClient.post(
      `${environment.CONFLUENCE_API_ENDPOINT}/confluence/cron/${confluenceId}`,
      updateCronDto,
      { responseType: "json" },
    );
  }
}

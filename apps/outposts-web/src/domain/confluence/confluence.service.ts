import { HttpClient } from "@angular/common/http";
import { Injectable, inject } from "@angular/core";
import { environment } from "@/environments/environment";
import type { ConfluenceDto } from "./bindings/ConfluenceDto";
import type { ConfluenceUpdateCronDto } from "./bindings/ConfluenceUpdateCronDto";
import type { ConfluenceUpdateDto } from "./bindings/ConfluenceUpdateDto";
import type { ProfileCreationDto } from "./bindings/ProfileCreationDto";
import type { ProfileDto } from "./bindings/ProfileDto";
import type { ProfilePreviewDto } from "./bindings/ProfilePreviewDto";
import type { ProfilePreviewRequestDto } from "./bindings/ProfilePreviewRequestDto";
import type { ProfileUpdateDto } from "./bindings/ProfileUpdateDto";
import type { SubscribeSourceCreationDto } from "./bindings/SubscribeSourceCreationDto";
import type { SubscribeSourceDto } from "./bindings/SubscribeSourceDto";
import type { SubscribeSourceUpdateDto } from "./bindings/SubscribeSourceUpdateDto";
import type { SupplicantSummaryDto } from "./bindings/SupplicantSummaryDto";
import type { UUIDV7 } from "./bindings/UUIDV7";
import type { VlanConfig } from "./bindings/VlanConfig";
import type { VlanNetwork } from "./bindings/VlanNetwork";
import type { VlanSupplicant } from "./bindings/VlanSupplicant";
import type { ConfluenceVlansUpdateDto } from "./bindings/ConfluenceVlansUpdateDto";

@Injectable()
export class ConfluenceService {
  protected readonly apiEndpoint = environment.CONFLUENCE_API_ENDPOINT;
  protected httpClient: HttpClient = inject(HttpClient);

  getAllConfluences() {
    return this.httpClient.get<ConfluenceDto[]>(`${this.apiEndpoint}/confluences`, {
      responseType: "json",
    });
  }

  addConfluence() {
    return this.httpClient.post<ConfluenceDto>(
      `${this.apiEndpoint}/confluences`,
      {},
      {
        responseType: "json",
      },
    );
  }

  removeConfluence(id: string) {
    return this.httpClient.delete(`${this.apiEndpoint}/confluences/${id}`, {
      responseType: "json",
    });
  }

  getConfluenceById(id: string) {
    return this.httpClient.get<ConfluenceDto>(`${this.apiEndpoint}/confluences/${id}`, {
      responseType: "json",
    });
  }

  updateConfluence(id: string, form: ConfluenceUpdateDto) {
    return this.httpClient.put<ConfluenceDto>(`${this.apiEndpoint}/confluences/${id}`, form, {
      responseType: "json",
    });
  }

  getVlanCatalog() {
    return this.httpClient.get<VlanConfig>(`${this.apiEndpoint}/vlans`);
  }

  aggregateVlanRoutes(routes: string[]) {
    return this.httpClient.post<string[]>(`${this.apiEndpoint}/vlans/routes/aggregate`, routes);
  }

  saveVlan(network: VlanNetwork) {
    const url = `${this.apiEndpoint}/vlans`;
    return network.id
      ? this.httpClient.put<VlanNetwork>(`${url}/${network.id}`, network)
      : this.httpClient.post<VlanNetwork>(url, network);
  }

  removeVlan(id: string) {
    return this.httpClient.delete<void>(`${this.apiEndpoint}/vlans/${id}`);
  }

  getSupplicants() {
    return this.httpClient.get<SupplicantSummaryDto[]>(`${this.apiEndpoint}/supplicants`);
  }

  saveSupplicant(supplicant: VlanSupplicant) {
    const url = `${this.apiEndpoint}/supplicants`;
    return supplicant.id
      ? this.httpClient.put<VlanSupplicant>(`${url}/${supplicant.id}`, supplicant)
      : this.httpClient.post<VlanSupplicant>(url, supplicant);
  }

  removeSupplicant(id: string) {
    return this.httpClient.delete<void>(`${this.apiEndpoint}/supplicants/${id}`);
  }

  updateConfluenceVlans(id: UUIDV7, input: ConfluenceVlansUpdateDto) {
    return this.httpClient.put<UUIDV7[]>(`${this.apiEndpoint}/confluences/${id}/vlans`, input);
  }

  addSubscribeSource(form: SubscribeSourceCreationDto) {
    return this.httpClient.post<SubscribeSourceDto>(`${this.apiEndpoint}/subscribe_sources`, form, {
      responseType: "json",
    });
  }

  removeSubscribeSource(id: string) {
    return this.httpClient.delete(`${this.apiEndpoint}/subscribe_sources/${id}`, {
      responseType: "json",
    });
  }

  updateSubscribeSource(id: string, form: SubscribeSourceUpdateDto) {
    return this.httpClient.put<SubscribeSourceDto>(
      `${this.apiEndpoint}/subscribe_sources/${id}`,
      form,
      {
        responseType: "json",
      },
    );
  }

  syncConfluence(id: string) {
    return this.httpClient.post<ConfluenceDto>(
      `${this.apiEndpoint}/confluences/${id}/sync`,
      {},
      {
        responseType: "json",
      },
    );
  }

  syncSubscribeSource(id: string) {
    return this.httpClient.post<SubscribeSourceDto>(
      `${this.apiEndpoint}/subscribe_sources/${id}/sync`,
      {},
      {
        responseType: "json",
      },
    );
  }

  muxConfluence(id: string) {
    return this.httpClient.post<ConfluenceDto>(
      `${this.apiEndpoint}/confluences/${id}/mux`,
      {},
      {
        responseType: "json",
      },
    );
  }

  addProfile(form: ProfileCreationDto) {
    return this.httpClient.post<ProfileDto>(`${this.apiEndpoint}/profiles`, form, {
      responseType: "json",
    });
  }

  removeProfile(id: string) {
    return this.httpClient.delete(`${this.apiEndpoint}/profiles/${id}`, {
      responseType: "json",
    });
  }

  updateProfile(id: string, form: ProfileUpdateDto) {
    return this.httpClient.put<ProfileDto>(`${this.apiEndpoint}/profiles/${id}`, form, {
      responseType: "json",
    });
  }

  /** Owner-only render of a saved profile for a simulated subscription request. */
  previewProfile(id: string, request: ProfilePreviewRequestDto) {
    return this.httpClient.post<ProfilePreviewDto>(
      `${this.apiEndpoint}/profiles/${id}/preview`,
      request,
    );
  }

  getProfileUrl(resourceToken: ProfileDto["resource_token"]) {
    return `${this.apiEndpoint}/profile_token/${resourceToken}`;
  }

  updateConfluenceCron(confluenceId: string, updateCronDto: ConfluenceUpdateCronDto) {
    return this.httpClient.put(
      `${this.apiEndpoint}/confluences/${confluenceId}/cron`,
      updateCronDto,
      { responseType: "json" },
    );
  }
}

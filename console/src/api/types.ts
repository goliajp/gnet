// Hand-maintained mirror of the dispatcher / console / relay admin
// API shapes. No codegen — when an endpoint moves, this file and the
// Rust side move in the same PR.

// host-role payload depends on which binary is serving. Dispatcher
// + relay carry network identity; the SaaS console is multi-tenant
// and only knows its role + version.
export type HostRoleResponse =
  | {
      role: "dispatcher";
      version: string;
      network_id: string;
      network_name: string;
    }
  | {
      role: "relay";
      version: string;
      network_id: string;
      network_name: string;
    }
  | {
      role: "console";
      version: string;
    };

// Dispatcher's local-admin /api/auth/me response.
export type MeResponse = {
  user_id: string;
  username: string;
  role: string;
};

// Console's email-auth /api/auth/me response. Different shape from
// the dispatcher's (no network role, has email + verification).
export type ConsoleMeResponse = {
  user_id: string;
  email: string | null;
  verified: boolean;
};

export type LoginRequest = {
  username: string;
  password: string;
};

export type LoginResponse = MeResponse;

// Console email-auth payloads.
export type EmailLoginRequest = {
  email: string;
  password: string;
};

export type EmailRegisterRequest = {
  email: string;
  password: string;
};

// User's federated networks (Mode A SaaS + Mode C federated self-host).
export type UserNetworkRow = {
  id: string;
  network_label: string;
  dispatcher_endpoint: string;
  mode: "saas" | "self_host";
  role: string;
  created_at: string;
};

export type RegisterNetworkRequest = {
  network_label: string;
  dispatcher_endpoint: string;
};

export type RegisterNetworkResponse = {
  id: string;
  network_label: string;
  dispatcher_endpoint: string;
  mode: "self_host";
  // Plaintext federation token — shown to the user EXACTLY ONCE.
  federation_token: string;
};

export type SetupRequest = {
  token: string;
  username: string;
  password: string;
};

export type SetupResponse = {
  user_id: string;
  username: string;
};

export type NetworkResponse = {
  id: string;
  name: string;
  overlay_v4_prefix_hex: string;
  overlay_v6_prefix_hex: string;
  created_at: string;
};

export type DeviceResponse = {
  id: string;
  alias: string;
  x25519_pubkey_hex: string;
  vip_v4: string;
  vip_v6: string;
  relay_eligible: boolean;
  last_reflexive: string | null;
  last_seen_at: string | null;
  created_at: string;
};

// Hand-maintained mirror of the dispatcher / console / relay admin
// API shapes. No codegen — when an endpoint moves, this file and the
// Rust side move in the same PR.

export type HostRoleResponse = {
  role: "dispatcher" | "relay" | "console";
  version: string;
  network_id: string;
  network_name: string;
};

export type MeResponse = {
  user_id: string;
  username: string;
  role: string;
};

export type LoginRequest = {
  username: string;
  password: string;
};

export type LoginResponse = MeResponse;

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

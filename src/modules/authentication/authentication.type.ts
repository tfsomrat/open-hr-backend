export type RefreshTokenType = {
  token: string;
  device: string;
};

export type AuthenticationType = {
  user_id: string;
  max_device: number;
  refresh_tokens: RefreshTokenType[];
  pass_reset_token?: {
    otp_hash?: string;
    expires?: string;
  };
};

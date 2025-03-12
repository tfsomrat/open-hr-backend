import mongoose, { model } from "mongoose";
import { AuthenticationType } from "./authentication.type";

// password verification token model
export const authenticationSchema = new mongoose.Schema<AuthenticationType>(
  {
    user_id: {
      type: String,
      required: true,
      unique: true,
    },
    max_device: {
      type: Number,
      required: true,
      default: 3,
    },
    refresh_tokens: [
      {
        token: {
          type: String,
          required: true,
        },
        device: {
          type: String,
          required: true,
        },
      },
    ],
    pass_reset_token: {
      otp_hash: {
        type: String,
      },
      expires: {
        type: String,
      },
    },
  },
  {
    timestamps: true,
  }
);

export const Authentication = model<AuthenticationType>(
  "authentication",
  authenticationSchema
);

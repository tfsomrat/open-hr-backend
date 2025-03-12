import variables from "@/config/variables";
import { jwtHelpers } from "@/lib/jwtTokenHelper";
import { mailSender } from "@/lib/mailSender";
import bcrypt from "bcrypt";
import { JwtPayload, Secret } from "jsonwebtoken";
import mongoose from "mongoose";
import NodeCache from "node-cache";
import { Employee } from "../employee/employee.model";
import { Authentication } from "./authentication.model";
import { AuthenticationType } from "./authentication.type";

// Helper to update refresh tokens for a user
const updateRefreshTokens = async (
  userId: string,
  device: string,
  refreshToken: string
) => {
  const newTokenEntry = {
    token: refreshToken,
    device: device,
  };

  let authDoc = await Authentication.findOne({ user_id: userId });
  if (authDoc) {
    let tokens = authDoc.refresh_tokens || [];
    if (tokens.length >= authDoc.max_device) {
      tokens.shift();
    }
    tokens.push(newTokenEntry);
    authDoc.refresh_tokens = tokens;
    await authDoc.save();
  } else {
    await Authentication.create({
      user_id: userId,
      max_device: 3,
      refresh_tokens: [newTokenEntry],
    });
  }
};

// password login
const passwordLoginService = async (
  email: string,
  password: string,
  device: string
) => {
  const isUserExist = await Employee.findOne({ work_email: email });

  if (!isUserExist) throw Error("User not found");

  const isMatch = await bcrypt.compare(
    password,
    isUserExist.password as string
  );

  if (!isMatch && isUserExist.password) {
    throw Error("Incorrect password");
  }

  const accessToken = jwtHelpers.createToken(
    {
      id: isUserExist.id,
      role: isUserExist.role,
    },
    variables.jwt_secret as Secret,
    variables.jwt_expire as string
  );

  const refreshToken = jwtHelpers.createToken(
    {
      id: isUserExist.id,
      role: isUserExist.role,
    },
    variables.jwt_refresh_secret as Secret,
    variables.jwt_refresh_expire as string
  );

  await updateRefreshTokens(isUserExist.id, device, refreshToken);

  const userDetails = {
    userId: isUserExist.id as string,
    name: isUserExist.name as string,
    email: isUserExist.work_email as string,
    image: isUserExist?.image as string,
    role: isUserExist.role as string,
    accessToken: accessToken,
    refreshToken: refreshToken,
  };

  return userDetails;
};

// oauth login
const oauthLoginService = async (email: string, device: string) => {
  const isUserExist = await Employee.findOne({ work_email: email });

  if (!isUserExist) {
    throw new Error("User not found");
  }

  const userDetails = {
    userId: isUserExist.id,
    name: isUserExist.name,
    email: isUserExist.work_email,
    image: isUserExist.image,
    role: isUserExist.role,
    accessToken: "",
    refreshToken: "",
  };

  const accessToken = jwtHelpers.createToken(
    { user_id: isUserExist.id, role: isUserExist.role },
    variables.jwt_secret as Secret,
    variables.jwt_expire as string
  );

  const refreshToken = jwtHelpers.createToken(
    { user_id: isUserExist.id, role: isUserExist.role },
    variables.jwt_refresh_secret as Secret,
    variables.jwt_refresh_expire as string
  );

  await updateRefreshTokens(isUserExist.id, device, refreshToken);

  userDetails.accessToken = accessToken;
  userDetails.refreshToken = refreshToken;

  return userDetails;
};

// token login
const tokenLoginService = async (token: string, device: string) => {
  const decodedToken = jwtHelpers.verifyToken(
    token,
    variables.jwt_secret as Secret
  );

  const userId = decodedToken.id;
  const employee = await Employee.findOne({ id: userId });

  if (!employee) {
    throw new Error("User not found");
  }

  const userDetails = {
    userId: employee.id,
    name: employee.name,
    email: employee.work_email,
    image: employee.image,
    role: employee.role,
    accessToken: "",
    refreshToken: "",
  };

  const accessToken = jwtHelpers.createToken(
    { user_id: employee.id, role: employee.role },
    variables.jwt_secret as Secret,
    variables.jwt_expire as string
  );

  const refreshToken = jwtHelpers.createToken(
    { user_id: employee.id, role: employee.role },
    variables.jwt_refresh_secret as Secret,
    variables.jwt_refresh_expire as string
  );

  await updateRefreshTokens(employee.id, device, refreshToken);

  userDetails.accessToken = accessToken;
  userDetails.refreshToken = refreshToken;

  return userDetails;
};

// user verification for password recovery
const verifyUserService = async (email: string, currentTime: string) => {
  const isUserExist = await Employee.findOne({ work_email: email });
  if (!isUserExist) {
    throw Error("Something went wrong Try again");
  } else {
    await sendVerificationOtp(isUserExist.id!, email, currentTime);
    return isUserExist;
  }
};

// send verification otp
const sendVerificationOtp = async (
  id: string,
  email: string,
  currentTime: string
) => {
  const otp = `${Math.floor(1000 + Math.random() * 9000)}`;
  const getCurrentTime = new Date(currentTime);
  const expiringTime = new Date(
    getCurrentTime.setMinutes(getCurrentTime.getMinutes() + 5)
  ).toISOString();

  const userVerification = {
    pass_reset_token: {
      otp_hash: await bcrypt.hash(otp, variables.salt),
      expires: expiringTime,
    },
  };

  await Authentication.updateOne(
    { user_id: id },
    { $set: userVerification },
    { upsert: true, new: true }
  );

  await mailSender.otpSender(email, otp);
};

// verify otp
const verifyOtpService = async (
  email: string,
  otp: string,
  currentTime: string
) => {
  if (!otp && !email) {
    throw Error("Empty details are not allowed");
  } else {
    const user = await Employee.findOne({ work_email: email });
    const verificationToken = await Authentication.findOne({
      user_id: user?.id,
    });
    if (!verificationToken) {
      throw Error("OTP not found");
    } else {
      const userId = verificationToken.user_id;
      const { otp_hash: hashedOtp, expires } =
        verificationToken.pass_reset_token || {};

      // Check if the OTP is still valid
      if (expires && new Date(expires) > new Date(currentTime)) {
        if (!hashedOtp) {
          throw new Error("OTP not found");
        }
        const compareOtp = await bcrypt.compare(otp, hashedOtp);
        await Employee.updateOne({ id: userId }, { $set: { verified: true } });

        // Check if the OTP is correct
        if (!compareOtp) {
          throw Error("Incorrect OTP!");
        }

        // Check if the OTP has expired
      } else {
        throw Error("OTP Expired");
      }
    }
  }
};

// reset password
const resetPasswordService = async (email: string, password: string) => {
  const session = await mongoose.startSession();
  try {
    session.startTransaction();
    const hashedPassword = await bcrypt.hash(password, variables.salt);
    const resetPassword = await Employee.findOneAndUpdate(
      { work_email: email },
      {
        $set: {
          password: hashedPassword,
        },
      },
      { session, new: true }
    );

    if (!resetPassword) {
      throw new Error("Something went wrong");
    }

    await session.commitTransaction();
    await session.endSession();
  } catch (error) {
    await session.abortTransaction();
    await session.endSession();
  }
};

// update password
const updatePasswordService = async (
  id: string,
  current_password: string,
  new_password: string
) => {
  const user = await Employee.findOne({ id: id });

  if (!user) {
    throw new Error("Something went wrong");
  }

  if (user.password) {
    const isMatch = await bcrypt.compare(current_password, user.password);

    if (!isMatch) {
      throw new Error("Incorrect password");
    }
  }

  const hashedPassword = await bcrypt.hash(new_password, variables.salt);

  await Employee.updateOne(
    { id: id },
    {
      $set: {
        password: hashedPassword,
      },
    },
    { new: true, upsert: true }
  );
};

// reset password otp
const resetPasswordOtpService = async (
  id: string
): Promise<AuthenticationType | null> => {
  if (!id) {
    throw Error("Invalid request");
  } else {
    const isUserOtp = await Authentication.findOne({
      user_id: id,
    });

    if (!isUserOtp) {
      throw Error("Invalid user_id");
    } else {
      return isUserOtp;
    }
  }
};

// resend verification token
const resendOtpService = async (email: string, currentTime: string) => {
  const user = await Employee.findOne({ work_email: email });
  const user_id = user?.id;
  if (!email) {
    throw Error("Empty user information");
  } else {
    await sendVerificationOtp(user_id, email, currentTime);
  }
};

// refresh token cache for 10 seconds
const refreshTokenCache = new NodeCache({ stdTTL: 10 });

// refresh token service
export const refreshTokenService = async (
  refreshToken: string,
  device: string
) => {
  if (!refreshToken) {
    throw new Error("Refresh token is required");
  }

  try {
    // Verify token
    let decodedToken: JwtPayload;
    try {
      decodedToken = jwtHelpers.verifyToken(
        refreshToken,
        variables.jwt_refresh_secret as Secret
      );
    } catch (verifyError: any) {
      console.error("Token verification failed:", verifyError.message);
      throw new Error(`Token verification error: ${verifyError.message}`);
    }

    const { id: userId, role } = decodedToken;
    if (!userId) {
      throw new Error("Invalid token payload");
    }

    // Create a user-specific cache key
    const cacheKey = `user:${userId}`;

    // Check for cached response
    const cached = refreshTokenCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    // Find user's token in database
    let authDoc: any = null;
    let retries = 3;
    while (retries > 0) {
      try {
        authDoc = await Authentication.findOne({ user_id: userId });
        break;
      } catch (err) {
        retries--;
        if (retries === 0) throw err;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }

    if (!authDoc) {
      throw new Error("User not found");
    }

    // Check if the provided refreshToken exists in refresh_tokens array
    const tokenIndex = authDoc.refresh_tokens.findIndex(
      (entry: any) => entry.token === refreshToken
    );
    if (tokenIndex === -1) {
      console.error(`No valid refresh token found for user: ${userId}`);
      throw new Error("User has been logged out");
    }

    // Remove the old token
    authDoc.refresh_tokens.splice(tokenIndex, 1);

    // Generate new tokens
    const newAccessToken = jwtHelpers.createToken(
      {
        id: userId,
        role: role,
      },
      variables.jwt_secret as Secret,
      variables.jwt_expire as string
    );

    const newRefreshToken = jwtHelpers.createToken(
      {
        id: userId,
        role: role,
      },
      variables.jwt_refresh_secret as Secret,
      variables.jwt_refresh_expire as string
    );

    // Add the new token to the array
    const newTokenEntry = {
      token: newRefreshToken,
      device: device,
    };

    if (authDoc.refresh_tokens.length >= authDoc.max_device) {
      authDoc.refresh_tokens.shift();
    }
    authDoc.refresh_tokens.push(newTokenEntry);
    await authDoc.save();

    const responseData = {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    };

    // Cache the response using just the user ID
    refreshTokenCache.set(cacheKey, responseData);

    return responseData;
  } catch (error: any) {
    console.error("Refresh token error:", error.message);
    throw new Error("Invalid refresh token");
  }
};

// export services
export const authenticationService = {
  passwordLoginService,
  oauthLoginService,
  tokenLoginService,
  verifyUserService,
  resendOtpService,
  verifyOtpService,
  resetPasswordService,
  updatePasswordService,
  resetPasswordOtpService,
  refreshTokenService,
};

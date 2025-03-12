"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.authenticationService = exports.refreshTokenService = void 0;
const variables_1 = __importDefault(require("../../config/variables"));
const jwtTokenHelper_1 = require("../../lib/jwtTokenHelper");
const mailSender_1 = require("../../lib/mailSender");
const bcrypt_1 = __importDefault(require("bcrypt"));
const mongoose_1 = __importDefault(require("mongoose"));
const node_cache_1 = __importDefault(require("node-cache"));
const employee_model_1 = require("../employee/employee.model");
const authentication_model_1 = require("./authentication.model");
// Helper to update refresh tokens for a user
const updateRefreshTokens = (userId, device, refreshToken) => __awaiter(void 0, void 0, void 0, function* () {
    const newTokenEntry = {
        token: refreshToken,
        device: device,
    };
    let authDoc = yield authentication_model_1.Authentication.findOne({ user_id: userId });
    if (authDoc) {
        // First check if this device already exists
        const existingDeviceIndex = authDoc.refresh_tokens.findIndex((entry) => entry.device === device);
        if (existingDeviceIndex !== -1) {
            // Update existing device token
            authDoc.refresh_tokens[existingDeviceIndex].token = refreshToken;
        }
        else {
            // Add new device, but enforce max_device limit
            if (authDoc.refresh_tokens.length >= authDoc.max_device) {
                authDoc.refresh_tokens.shift();
            }
            authDoc.refresh_tokens.push(newTokenEntry);
        }
        yield authDoc.save();
    }
    else {
        // Create new auth document
        yield authentication_model_1.Authentication.create({
            user_id: userId,
            refresh_tokens: [newTokenEntry],
        });
    }
});
// password login
const passwordLoginService = (email, password, device) => __awaiter(void 0, void 0, void 0, function* () {
    const isUserExist = yield employee_model_1.Employee.findOne({ work_email: email });
    if (!isUserExist)
        throw Error("User not found");
    const isMatch = yield bcrypt_1.default.compare(password, isUserExist.password);
    if (!isMatch && isUserExist.password) {
        throw Error("Incorrect password");
    }
    const accessToken = jwtTokenHelper_1.jwtHelpers.createToken({
        id: isUserExist.id,
        role: isUserExist.role,
    }, variables_1.default.jwt_secret, variables_1.default.jwt_expire);
    const refreshToken = jwtTokenHelper_1.jwtHelpers.createToken({
        id: isUserExist.id,
        role: isUserExist.role,
    }, variables_1.default.jwt_refresh_secret, variables_1.default.jwt_refresh_expire);
    yield updateRefreshTokens(isUserExist.id, device, refreshToken);
    const userDetails = {
        userId: isUserExist.id,
        name: isUserExist.name,
        email: isUserExist.work_email,
        image: isUserExist === null || isUserExist === void 0 ? void 0 : isUserExist.image,
        role: isUserExist.role,
        accessToken: accessToken,
        refreshToken: refreshToken,
    };
    return userDetails;
});
// oauth login
const oauthLoginService = (email, device) => __awaiter(void 0, void 0, void 0, function* () {
    const isUserExist = yield employee_model_1.Employee.findOne({ work_email: email });
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
    const accessToken = jwtTokenHelper_1.jwtHelpers.createToken({ user_id: isUserExist.id, role: isUserExist.role }, variables_1.default.jwt_secret, variables_1.default.jwt_expire);
    const refreshToken = jwtTokenHelper_1.jwtHelpers.createToken({ user_id: isUserExist.id, role: isUserExist.role }, variables_1.default.jwt_refresh_secret, variables_1.default.jwt_refresh_expire);
    yield updateRefreshTokens(isUserExist.id, device, refreshToken);
    userDetails.accessToken = accessToken;
    userDetails.refreshToken = refreshToken;
    return userDetails;
});
// token login
const tokenLoginService = (token, device) => __awaiter(void 0, void 0, void 0, function* () {
    const decodedToken = jwtTokenHelper_1.jwtHelpers.verifyToken(token, variables_1.default.jwt_secret);
    const userId = decodedToken.id;
    const employee = yield employee_model_1.Employee.findOne({ id: userId });
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
    const accessToken = jwtTokenHelper_1.jwtHelpers.createToken({ user_id: employee.id, role: employee.role }, variables_1.default.jwt_secret, variables_1.default.jwt_expire);
    const refreshToken = jwtTokenHelper_1.jwtHelpers.createToken({ user_id: employee.id, role: employee.role }, variables_1.default.jwt_refresh_secret, variables_1.default.jwt_refresh_expire);
    yield updateRefreshTokens(employee.id, device, refreshToken);
    userDetails.accessToken = accessToken;
    userDetails.refreshToken = refreshToken;
    return userDetails;
});
// user verification for password recovery
const verifyUserService = (email, currentTime) => __awaiter(void 0, void 0, void 0, function* () {
    const isUserExist = yield employee_model_1.Employee.findOne({ work_email: email });
    if (!isUserExist) {
        throw Error("Something went wrong Try again");
    }
    else {
        yield sendVerificationOtp(isUserExist.id, email, currentTime);
        return isUserExist;
    }
});
// send verification otp
const sendVerificationOtp = (id, email, currentTime) => __awaiter(void 0, void 0, void 0, function* () {
    const otp = `${Math.floor(1000 + Math.random() * 9000)}`;
    const getCurrentTime = new Date(currentTime);
    const expiringTime = new Date(getCurrentTime.setMinutes(getCurrentTime.getMinutes() + 5)).toISOString();
    const userVerification = {
        pass_reset_token: {
            otp_hash: yield bcrypt_1.default.hash(otp, variables_1.default.salt),
            expires: expiringTime,
        },
    };
    yield authentication_model_1.Authentication.updateOne({ user_id: id }, { $set: userVerification }, { upsert: true, new: true });
    yield mailSender_1.mailSender.otpSender(email, otp);
});
// verify otp
const verifyOtpService = (email, otp, currentTime) => __awaiter(void 0, void 0, void 0, function* () {
    if (!otp && !email) {
        throw Error("Empty details are not allowed");
    }
    else {
        const user = yield employee_model_1.Employee.findOne({ work_email: email });
        const verificationToken = yield authentication_model_1.Authentication.findOne({
            user_id: user === null || user === void 0 ? void 0 : user.id,
        });
        if (!verificationToken) {
            throw Error("OTP not found");
        }
        else {
            const userId = verificationToken.user_id;
            const { otp_hash: hashedOtp, expires } = verificationToken.pass_reset_token || {};
            // Check if the OTP is still valid
            if (expires && new Date(expires) > new Date(currentTime)) {
                if (!hashedOtp) {
                    throw new Error("OTP not found");
                }
                const compareOtp = yield bcrypt_1.default.compare(otp, hashedOtp);
                yield employee_model_1.Employee.updateOne({ id: userId }, { $set: { verified: true } });
                // Check if the OTP is correct
                if (!compareOtp) {
                    throw Error("Incorrect OTP!");
                }
                // Check if the OTP has expired
            }
            else {
                throw Error("OTP Expired");
            }
        }
    }
});
// reset password
const resetPasswordService = (email, password) => __awaiter(void 0, void 0, void 0, function* () {
    const session = yield mongoose_1.default.startSession();
    try {
        session.startTransaction();
        const hashedPassword = yield bcrypt_1.default.hash(password, variables_1.default.salt);
        const resetPassword = yield employee_model_1.Employee.findOneAndUpdate({ work_email: email }, {
            $set: {
                password: hashedPassword,
            },
        }, { session, new: true });
        if (!resetPassword) {
            throw new Error("Something went wrong");
        }
        yield session.commitTransaction();
        yield session.endSession();
    }
    catch (error) {
        yield session.abortTransaction();
        yield session.endSession();
    }
});
// update password
const updatePasswordService = (id, current_password, new_password) => __awaiter(void 0, void 0, void 0, function* () {
    const user = yield employee_model_1.Employee.findOne({ id: id });
    if (!user) {
        throw new Error("Something went wrong");
    }
    if (user.password) {
        const isMatch = yield bcrypt_1.default.compare(current_password, user.password);
        if (!isMatch) {
            throw new Error("Incorrect password");
        }
    }
    const hashedPassword = yield bcrypt_1.default.hash(new_password, variables_1.default.salt);
    yield employee_model_1.Employee.updateOne({ id: id }, {
        $set: {
            password: hashedPassword,
        },
    }, { new: true, upsert: true });
});
// reset password otp
const resetPasswordOtpService = (id) => __awaiter(void 0, void 0, void 0, function* () {
    if (!id) {
        throw Error("Invalid request");
    }
    else {
        const isUserOtp = yield authentication_model_1.Authentication.findOne({
            user_id: id,
        });
        if (!isUserOtp) {
            throw Error("Invalid user_id");
        }
        else {
            return isUserOtp;
        }
    }
});
// resend verification token
const resendOtpService = (email, currentTime) => __awaiter(void 0, void 0, void 0, function* () {
    const user = yield employee_model_1.Employee.findOne({ work_email: email });
    const user_id = user === null || user === void 0 ? void 0 : user.id;
    if (!email) {
        throw Error("Empty user information");
    }
    else {
        yield sendVerificationOtp(user_id, email, currentTime);
    }
});
// refresh token cache for 10 seconds
const refreshTokenCache = new node_cache_1.default({ stdTTL: 10 });
// refresh token service
const refreshTokenService = (refreshToken, device) => __awaiter(void 0, void 0, void 0, function* () {
    if (!refreshToken) {
        throw new Error("Refresh token is required");
    }
    if (!device) {
        throw new Error("Device identifier is required");
    }
    try {
        // Verify token
        let decodedToken;
        try {
            decodedToken = jwtTokenHelper_1.jwtHelpers.verifyToken(refreshToken, variables_1.default.jwt_refresh_secret);
        }
        catch (verifyError) {
            console.error("Token verification failed:", verifyError.message);
            throw new Error(`Token verification error: ${verifyError.message}`);
        }
        const { id: userId, role } = decodedToken;
        if (!userId) {
            throw new Error("Invalid token payload");
        }
        // Create a device-specific cache key
        const cacheKey = `user:${userId}:device:${device}`;
        // Check for cached response
        const cached = refreshTokenCache.get(cacheKey);
        if (cached) {
            return cached;
        }
        // Find user's auth record in database with retry logic
        let authDoc = null;
        let retries = 3;
        while (retries > 0) {
            try {
                // Use a transaction to ensure atomic updates
                const session = yield authentication_model_1.Authentication.startSession();
                session.startTransaction();
                try {
                    authDoc = yield authentication_model_1.Authentication.findOne({ user_id: userId }).session(session);
                    if (!authDoc) {
                        yield session.abortTransaction();
                        session.endSession();
                        throw new Error("User not found");
                    }
                    // Check if the provided refreshToken exists in refresh_tokens array
                    const tokenIndex = authDoc.refresh_tokens.findIndex((entry) => entry.token === refreshToken);
                    if (tokenIndex === -1) {
                        yield session.abortTransaction();
                        session.endSession();
                        throw new Error("User has been logged out");
                    }
                    // Remove the old token
                    authDoc.refresh_tokens.splice(tokenIndex, 1);
                    // Generate new tokens
                    const newAccessToken = jwtTokenHelper_1.jwtHelpers.createToken({
                        id: userId,
                        role: role,
                    }, variables_1.default.jwt_secret, variables_1.default.jwt_expire);
                    const newRefreshToken = jwtTokenHelper_1.jwtHelpers.createToken({
                        id: userId,
                        role: role,
                    }, variables_1.default.jwt_refresh_secret, variables_1.default.jwt_refresh_expire);
                    // Add the new token to the array
                    const newTokenEntry = {
                        token: newRefreshToken,
                        device: device,
                    };
                    authDoc.refresh_tokens.push(newTokenEntry);
                    // Ensure we don't exceed max_device limit
                    if (authDoc.refresh_tokens.length > authDoc.max_device) {
                        // Remove the oldest token(s) to maintain limit
                        const excess = authDoc.refresh_tokens.length - authDoc.max_device;
                        authDoc.refresh_tokens.splice(0, excess);
                    }
                    yield authDoc.save({ session });
                    yield session.commitTransaction();
                    session.endSession();
                    const responseData = {
                        accessToken: newAccessToken,
                        refreshToken: newRefreshToken,
                    };
                    // Cache the response using device-specific key
                    refreshTokenCache.set(cacheKey, responseData);
                    return responseData;
                }
                catch (error) {
                    yield session.abortTransaction();
                    session.endSession();
                    throw error;
                }
            }
            catch (err) {
                retries--;
                if (retries === 0)
                    throw err;
                yield new Promise((resolve) => setTimeout(resolve, 100));
            }
        }
        throw new Error("Could not complete database operation after retries");
    }
    catch (error) {
        console.error("Refresh token error:", error.message);
        throw new Error("Invalid refresh token");
    }
});
exports.refreshTokenService = refreshTokenService;
// export services
exports.authenticationService = {
    passwordLoginService,
    oauthLoginService,
    tokenLoginService,
    verifyUserService,
    resendOtpService,
    verifyOtpService,
    resetPasswordService,
    updatePasswordService,
    resetPasswordOtpService,
    refreshTokenService: exports.refreshTokenService,
};
//# sourceMappingURL=authentication.service.js.map
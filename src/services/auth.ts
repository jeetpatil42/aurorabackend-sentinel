import bcrypt from 'bcryptjs';
import { supabaseAdmin } from '../db/supabaseAdmin';
import { supabase } from '../db/client';
import { sendOTPEmail } from './email';
import { generateAccessToken, generateRefreshToken, TokenPayload } from '../utils/jwt';

export interface User {
  id: string;
  email: string;
  password_hash: string;
  name: string;
  role: 'student' | 'security' | 'admin';
  is_verified: boolean;
  security_approved: boolean;
  created_at: string;
}

const SALT_ROUNDS = 10;
const OTP_EXPIRY_MINUTES = 10;

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

export async function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export async function hashOTP(otp: string): Promise<string> {
  return bcrypt.hash(otp, SALT_ROUNDS);
}

export async function compareOTP(otp: string, hash: string): Promise<boolean> {
  return bcrypt.compare(otp, hash);
}

export async function generateOTP(): Promise<string> {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

export async function registerUser(
  email: string,
  password: string,
  role: 'student' | 'security' = 'student'
): Promise<User> {
  // Check if user already exists
  const { data: existingUser } = await supabaseAdmin
    .from('users')
    .select('id')
    .eq('email', email.toLowerCase())
    .single();

  if (existingUser) {
    throw new Error('User with this email already exists');
  }

  // Hash password
  const passwordHash = await hashPassword(password);

  // Create user
  const { data: user, error } = await supabaseAdmin
    .from('users')
    .insert({
      email: email.toLowerCase(),
      password_hash: passwordHash,
      name: email.split('@')[0],
      role,
      is_verified: false,
      security_approved: role !== 'security',
    })
    .select()
    .single();

  if (error) {
    throw new Error(`Failed to create user: ${error.message}`);
  }

  // Generate and send OTP
  const otp = await generateOTP();
  const otpHash = await hashOTP(otp);

  const expiresAt = new Date();
  expiresAt.setMinutes(expiresAt.getMinutes() + OTP_EXPIRY_MINUTES);

  await supabaseAdmin
    .from('otp_codes')
    .insert({
      user_id: user.id,
      otp_hash: otpHash,
      expires_at: expiresAt.toISOString(),
    });

  // Send OTP email
  await sendOTPEmail(email, otp);

  return user;
}

export async function verifyOTP(userId: string, otp: string): Promise<boolean> {
  // Get valid OTP codes for user
  const { data: otpCodes } = await supabaseAdmin
    .from('otp_codes')
    .select('*')
    .eq('user_id', userId)
    .gt('expires_at', new Date().toISOString())
    .order('created_at', { ascending: false });

  if (!otpCodes || otpCodes.length === 0) {
    return false;
  }

  // Check if any OTP matches
  for (const otpCode of otpCodes) {
    const match = await compareOTP(otp, otpCode.otp_hash);
    if (match) {
      // Mark user as verified
      await supabaseAdmin
        .from('users')
        .update({ is_verified: true })
        .eq('id', userId);

      // Delete used OTP codes
      await supabaseAdmin
        .from('otp_codes')
        .delete()
        .eq('user_id', userId);

      return true;
    }
  }

  return false;
}

export async function loginUser(email: string, password: string): Promise<{
  user: User;
  accessToken: string;
  refreshToken: string;
}> {
  // Try to get user from users table first (legacy users)
  const { data: user, error } = await supabaseAdmin
    .from('users')
    .select('*')
    .eq('email', email.toLowerCase())
    .single();

  if (user && !error) {
    // User exists in users table - verify password
    const passwordMatch = await comparePassword(password, user.password_hash);
    if (!passwordMatch) {
      throw new Error('Invalid email or password');
    }

    // Check if verified (verification is now handled by Supabase Auth, but we keep this for legacy users)
    if (!user.is_verified) {
      throw new Error('Please verify your email before logging in');
    }

    // Generate tokens
    const payload: TokenPayload = {
      userId: user.id,
      email: user.email,
      role: user.role,
    };

    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);

    return {
      user,
      accessToken,
      refreshToken,
    };
  }

  // User doesn't exist in users table - might be a Supabase Auth user
  // Try to verify password with Supabase Auth
  const { data: authData, error: authError } = await supabase.auth.signInWithPassword({
    email: email.toLowerCase(),
    password: password,
  });

  if (authError || !authData?.user) {
    throw new Error('Invalid email or password');
  }

  // User exists in Supabase Auth - get role from metadata
  const role = (authData.user.user_metadata?.role as 'student' | 'security') || 'student';
  const name = (authData.user.user_metadata?.name as string) || email.split('@')[0];
  
  // Create user in users table (sync from Supabase Auth)
  const placeholderHash = await hashPassword('placeholder-' + Date.now());
  const { data: newUser, error: createError } = await supabaseAdmin
    .from('users')
    .insert({
      email: email.toLowerCase(),
      password_hash: placeholderHash, // Placeholder - password verified via Supabase Auth
      name,
      role,
      is_verified: true, // Verified via Supabase Auth
      security_approved: role !== 'security',
    })
    .select()
    .single();

  if (createError || !newUser) {
    throw new Error('Failed to sync user account');
  }

  // Generate tokens
  const payload: TokenPayload = {
    userId: newUser.id,
    email: newUser.email,
    role: newUser.role,
  };

  const accessToken = generateAccessToken(payload);
  const refreshToken = generateRefreshToken(payload);

  return {
    user: newUser,
    accessToken,
    refreshToken,
  };
}

export async function getUserById(userId: string): Promise<User | null> {
  const { data, error } = await supabaseAdmin
    .from('users')
    .select('*')
    .eq('id', userId)
    .single();

  if (error || !data) {
    return null;
  }

  return data;
}

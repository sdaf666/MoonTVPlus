/* eslint-disable no-console */
import { NextRequest, NextResponse } from 'next/server';

import { getAuthInfoFromCookie, parseAuthInfo } from '@/lib/auth';
import { refreshAccessToken } from '@/lib/middleware-auth';
import { TOKEN_CONFIG } from '@/lib/refresh-token';

export const runtime = 'nodejs';

const STORAGE_TYPE =
  (process.env.NEXT_PUBLIC_STORAGE_TYPE as
    | 'localstorage'
    | 'redis'
    | 'upstash'
    | 'kvrocks'
    | undefined) || 'localstorage';

function buildRefreshResponse(authToken?: string | null) {
  const body: Record<string, unknown> = { ok: true };

  if (authToken) {
    body.token = authToken;
    const authInfo = parseAuthInfo(authToken);
    if (authInfo) {
      const { password, ...rest } = authInfo;
      body.auth = rest;
    }
  }

  return NextResponse.json(body);
}

export async function POST(request: NextRequest) {
  const authInfo = getAuthInfoFromCookie(request);

  if (!authInfo) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  if (STORAGE_TYPE === 'localstorage') {
    if (!authInfo.password || authInfo.password !== process.env.PASSWORD) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const authCookie = request.cookies.get('auth');
    if (!authCookie?.value) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const response = buildRefreshResponse(authCookie.value);
    const expires = new Date();
    expires.setDate(expires.getDate() + 60);
    response.cookies.set('auth', authCookie.value, {
      path: '/',
      expires,
      sameSite: 'lax',
      httpOnly: false,
      secure: false,
    });
    return response;
  }

  if (
    !authInfo.username ||
    !authInfo.role ||
    !authInfo.timestamp ||
    !authInfo.tokenId ||
    !authInfo.refreshToken ||
    !authInfo.refreshExpires
  ) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const now = Date.now();
  const accessTokenAge = now - authInfo.timestamp;
  const remainingAccessTime = TOKEN_CONFIG.ACCESS_TOKEN_AGE - accessTokenAge;
  const refreshWindow = 15 * 60 * 1000;

  if (remainingAccessTime <= 0) {
    return NextResponse.json(
      { error: 'Access token expired' },
      { status: 401 }
    );
  }

  if (remainingAccessTime > refreshWindow) {
    return NextResponse.json(
      { error: 'Refresh not allowed' },
      { status: 400 }
    );
  }

  if (now >= authInfo.refreshExpires) {
    return NextResponse.json(
      { error: 'Refresh token expired' },
      { status: 401 }
    );
  }

  const newAuthData = await refreshAccessToken(
    authInfo.username,
    authInfo.role,
    authInfo.tokenId,
    authInfo.refreshToken,
    authInfo.refreshExpires
  );

  if (!newAuthData) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const response = buildRefreshResponse(newAuthData);
  const expires = new Date(authInfo.refreshExpires);
  response.cookies.set('auth', newAuthData, {
    path: '/',
    expires,
    sameSite: 'lax',
    httpOnly: false,
    secure: false,
  });
  return response;
}

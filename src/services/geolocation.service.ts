import config from '../config/index.js';

// ============================================
// IP GEOLOCATION SERVICE
// ============================================

export interface GeoLocation {
    country: string;
    countryCode: string;
    region?: string;
    city?: string;
    timezone?: string;
    isp?: string;
    isVpn?: boolean;
    isProxy?: boolean;
    isTor?: boolean;
}

// Free IP geolocation API (ip-api.com)
// For production, consider: MaxMind, IPInfo, or IP2Location
const GEOIP_API_URL = 'http://ip-api.com/json';

/**
 * Get geolocation from IP address
 */
export async function getGeoLocation(ipAddress: string): Promise<GeoLocation | null> {
    try {
        // Skip private/local IPs
        if (isPrivateIp(ipAddress)) {
            return {
                country: 'Local',
                countryCode: 'LO',
                city: 'localhost',
            };
        }

        const response = await fetch(
            `${GEOIP_API_URL}/${ipAddress}?fields=status,country,countryCode,region,city,timezone,isp,proxy`,
            { signal: AbortSignal.timeout(5000) }
        );

        if (!response.ok) {
            console.error('Geolocation API error:', response.status);
            return null;
        }

        const data = await response.json();

        if (data.status !== 'success') {
            return null;
        }

        return {
            country: data.country,
            countryCode: data.countryCode,
            region: data.region,
            city: data.city,
            timezone: data.timezone,
            isp: data.isp,
            isProxy: data.proxy,
        };
    } catch (error) {
        console.error('Geolocation lookup failed:', error);
        return null;
    }
}

/**
 * Check if IP is a private/local address
 */
function isPrivateIp(ip: string): boolean {
    const privateRanges = [
        /^127\./,                    // Loopback
        /^10\./,                     // Private Class A
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Private Class B
        /^192\.168\./,               // Private Class C
        /^::1$/,                     // IPv6 loopback
        /^fe80:/i,                   // IPv6 link-local
        /^fc00:/i,                   // IPv6 unique local
    ];

    return privateRanges.some((range) => range.test(ip));
}

// ============================================
// LOCATION TRUST MANAGEMENT
// ============================================

import prisma from '../config/database.js';

/**
 * Check if login is from a new country
 */
export async function isNewCountryLogin(
    userId: string,
    countryCode: string
): Promise<boolean> {
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
            trustedCountries: true,
            lastLoginCountry: true,
        },
    });

    if (!user) return true;

    // First login - not "new"
    if (!user.lastLoginCountry) return false;

    // Check if country is trusted
    return !user.trustedCountries.includes(countryCode);
}

/**
 * Add country to trusted list
 */
export async function addTrustedCountry(
    userId: string,
    countryCode: string
): Promise<void> {
    await prisma.user.update({
        where: { id: userId },
        data: {
            trustedCountries: {
                push: countryCode,
            },
        },
    });
}

/**
 * Update user's last login location
 */
export async function updateLoginLocation(
    userId: string,
    ipAddress: string,
    geoLocation: GeoLocation | null
): Promise<void> {
    await prisma.user.update({
        where: { id: userId },
        data: {
            lastLoginIp: ipAddress,
            lastLoginCountry: geoLocation?.countryCode || null,
        },
    });

    // Update session with location
    const latestSession = await prisma.session.findFirst({
        where: { userId },
        orderBy: { createdAt: 'desc' },
    });

    if (latestSession) {
        await prisma.session.update({
            where: { id: latestSession.id },
            data: {
                country: geoLocation?.country,
                city: geoLocation?.city,
            },
        });
    }
}

// ============================================
// VPN/PROXY DETECTION
// ============================================

/**
 * Check if connection appears suspicious
 */
export function isSuspiciousConnection(geo: GeoLocation | null): boolean {
    if (!geo) return false;
    return Boolean(geo.isVpn || geo.isProxy || geo.isTor);
}

import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"
import { detectAnomaly, logSecurityEvent, checkRateLimit } from "@/lib/security"

// List of known bad IP addresses (in a real app, this would be loaded from a database or API)
const BLOCKED_IPS = [
  "192.0.2.1",
  "198.51.100.1",
  "203.0.113.1",
  // Add more as needed
]

// List of allowed HTTP methods
const ALLOWED_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]

export function middleware(request: NextRequest) {
  const response = NextResponse.next()

  // Get client IP
  const ip = request.ip || "unknown"

  // Check if IP is blocked
  if (BLOCKED_IPS.includes(ip)) {
    logSecurityEvent({
      type: "other",
      message: "Request from blocked IP address",
      data: { ip, url: request.url },
    })
    return new NextResponse("Forbidden", { status: 403 })
  }

  // Check HTTP method
  const method = request.method
  if (!ALLOWED_METHODS.includes(method)) {
    logSecurityEvent({
      type: "other",
      message: "Request with disallowed HTTP method",
      data: { ip, method, url: request.url },
    })
    return new NextResponse("Method Not Allowed", { status: 405 })
  }

  // Check for rate limiting
  const rateLimitKey = `${ip}:global`
  const isRateLimited = checkRateLimit(rateLimitKey, 100, 60000) // 100 requests per minute
  if (isRateLimited) {
    logSecurityEvent({
      type: "other",
      message: "Rate limit exceeded",
      data: { ip, url: request.url },
    })
    return new NextResponse("Too Many Requests", { status: 429 })
  }

  // Check for suspicious query parameters
  const url = new URL(request.url)
  const queryParams = Object.fromEntries(url.searchParams.entries())

  for (const [key, value] of Object.entries(queryParams)) {
    const anomalyCheck = detectAnomaly(value)
    if (anomalyCheck.isAnomaly) {
      logSecurityEvent({
        type: "anomaly",
        message: "Suspicious query parameter detected",
        data: { ip, param: key, value, reason: anomalyCheck.reason, url: request.url },
      })
      return new NextResponse("Bad Request", { status: 400 })
    }
  }

  // Add security headers
  response.headers.set("X-Content-Type-Options", "nosniff")
  response.headers.set("X-Frame-Options", "DENY")
  response.headers.set("X-XSS-Protection", "1; mode=block")
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin")
  response.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

  // In production, you would also add Content-Security-Policy
  if (process.env.NODE_ENV === "production") {
    response.headers.set(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self' 'unsafe-inline' https://trusted-cdn.com; style-src 'self' 'unsafe-inline' https://trusted-cdn.com; img-src 'self' data: https://trusted-cdn.com; font-src 'self' data: https://trusted-cdn.com; connect-src 'self' https://api.yourdomain.com;",
    )
  }

  return response
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     */
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
}


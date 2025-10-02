# Universal Authentication Server

A production-ready, reusable authentication server with enterprise-grade security.

## 🚀 Features

- ✅ Email/Password authentication with reset flow
- ✅ OAuth2 (Google, GitHub)
- ✅ Phone OTP authentication
- ✅ JWT tokens (access + refresh)
- ✅ Rate limiting & brute force protection
- ✅ Argon2 password hashing
- ✅ Encrypted database & TLS
- ✅ Token validation for any backend
- ✅ Audit logging & monitoring

## 📁 Project Structure

```
auth-server/
├── src/
│   ├── config/
│   │   ├── database.js
│   │   ├── security.js
│   │   ├── redis.js
│   │   └── oauth.js
│   ├── models/
│   │   ├── User.js
│   │   └── OTP.js
│   ├── middleware/
│   │   ├── rateLimiter.js
│   │   ├── validateToken.js
│   │   └── errorHandler.js
│   ├── controllers/
│   │   ├── authController.js
│   │   ├── oauthController.js
│   │   └── otpController.js
│   ├── routes/
│   │   └── auth.js
│   ├── utils/
│   │   ├── jwt.js
│   │   ├── password.js
│   │   ├── otp.js
│   │   └── logger.js
│   └── server.js
├── migrations/
│   └── 001_initial_schema.sql
├── .env.example
├── package.json
├── docker-compose.yml
└── README.md
```

## 🔧 Installation

### Prerequisites
- Node.js 18+
- PostgreSQL 14+
- Redis (for rate limiting & token blacklist)

### Setup

1. **Clone and install dependencies**
```bash
git clone https://github.com/yourusername/auth-server.git
cd auth-server
npm install
```

2. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your settings
```

3. **Run database migrations**
```bash
npm run migrate
```

4. **Start the server**
```bash
# Development
npm run dev

# Production
npm start
```

## 🔐 Environment Variables

```env
# Server
NODE_ENV=production
PORT=3000
BASE_URL=https://auth.yourdomain.com

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=auth_db
DB_USER=auth_user
DB_PASSWORD=strong_password
DB_SSL=true

# JWT Secrets (Use 256-bit keys)
JWT_ACCESS_SECRET=your-access-secret-min-32-chars
JWT_REFRESH_SECRET=your-refresh-secret-min-32-chars
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=7d

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=redis_password

# OAuth - Google
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_CALLBACK_URL=https://auth.yourdomain.com/auth/google/callback

# OAuth - GitHub
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_CALLBACK_URL=https://auth.yourdomain.com/auth/github/callback

# OTP Settings
OTP_EXPIRY_MINUTES=5
OTP_LENGTH=6

# SMS Provider (Twilio example)
TWILIO_ACCOUNT_SID=your-twilio-sid
TWILIO_AUTH_TOKEN=your-twilio-token
TWILIO_PHONE_NUMBER=+1234567890

# Email Provider (SendGrid example)
SENDGRID_API_KEY=your-sendgrid-key
FROM_EMAIL=noreply@yourdomain.com

# Security
BCRYPT_ROUNDS=12
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=5
```

## 📊 Database Schema

```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE,
    phone VARCHAR(20) UNIQUE,
    password_hash VARCHAR(255),
    provider_type VARCHAR(20) NOT NULL CHECK (provider_type IN ('local', 'google', 'github', 'otp')),
    provider_id VARCHAR(255),
    email_verified BOOLEAN DEFAULT FALSE,
    phone_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    CONSTRAINT check_auth_method CHECK (
        (provider_type = 'local' AND email IS NOT NULL AND password_hash IS NOT NULL) OR
        (provider_type IN ('google', 'github') AND provider_id IS NOT NULL) OR
        (provider_type = 'otp' AND phone IS NOT NULL)
    )
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_phone ON users(phone);
CREATE INDEX idx_users_provider ON users(provider_type, provider_id);

-- OTP codes table
CREATE TABLE otp_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone VARCHAR(20) NOT NULL,
    code VARCHAR(10) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    attempts INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_otp_phone ON otp_codes(phone, used, expires_at);

-- Refresh tokens table (for revocation)
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    ip_address VARCHAR(45),
    user_agent TEXT
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);

-- Audit log table
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    metadata JSONB,
    success BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at);

-- Password reset tokens
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_reset_tokens_user ON password_reset_tokens(user_id);
```

## 🛡️ API Endpoints

### Authentication

#### 1. Signup (Email/Password)
```http
POST /auth/signup
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd"
}

Response 201:
{
  "success": true,
  "data": {
    "userId": "uuid",
    "accessToken": "jwt-token",
    "refreshToken": "jwt-refresh-token",
    "expiresIn": 900
  }
}
```

#### 2. Login (Email/Password)
```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd"
}

Response 200:
{
  "success": true,
  "data": {
    "userId": "uuid",
    "accessToken": "jwt-token",
    "refreshToken": "jwt-refresh-token",
    "expiresIn": 900
  }
}
```

#### 3. Forgot Password
```http
POST /auth/forgot-password
Content-Type: application/json

{
  "email": "user@example.com"
}

Response 200:
{
  "success": true,
  "message": "Password reset email sent"
}
```

#### 4. Reset Password
```http
POST /auth/reset-password
Content-Type: application/json

{
  "token": "reset-token-from-email",
  "newPassword": "NewSecureP@ssw0rd"
}

Response 200:
{
  "success": true,
  "message": "Password reset successful"
}
```

#### 5. Refresh Token
```http
POST /auth/refresh
Content-Type: application/json

{
  "refreshToken": "jwt-refresh-token"
}

Response 200:
{
  "success": true,
  "data": {
    "accessToken": "new-jwt-token",
    "refreshToken": "new-jwt-refresh-token",
    "expiresIn": 900
  }
}
```

#### 6. Logout
```http
POST /auth/logout
Authorization: Bearer <access-token>
Content-Type: application/json

{
  "refreshToken": "jwt-refresh-token"
}

Response 200:
{
  "success": true,
  "message": "Logged out successfully"
}
```

### OAuth

#### 7. Google Login
```http
GET /auth/google
# Redirects to Google OAuth consent screen

Callback: GET /auth/google/callback?code=...
# Returns JWT tokens or redirects with tokens
```

#### 8. GitHub Login
```http
GET /auth/github
# Redirects to GitHub OAuth consent screen

Callback: GET /auth/github/callback?code=...
# Returns JWT tokens or redirects with tokens
```

### OTP (Phone)

#### 9. Request OTP
```http
POST /auth/otp/request
Content-Type: application/json

{
  "phone": "+1234567890"
}

Response 200:
{
  "success": true,
  "message": "OTP sent to phone",
  "expiresIn": 300
}
```

#### 10. Verify OTP
```http
POST /auth/otp/verify
Content-Type: application/json

{
  "phone": "+1234567890",
  "code": "123456"
}

Response 200:
{
  "success": true,
  "data": {
    "userId": "uuid",
    "accessToken": "jwt-token",
    "refreshToken": "jwt-refresh-token",
    "expiresIn": 900
  }
}
```

### Token Validation (For Backend Services)

#### 11. Validate Token
```http
POST /auth/validate
Authorization: Bearer <access-token>

Response 200:
{
  "success": true,
  "data": {
    "userId": "uuid",
    "email": "user@example.com",
    "provider": "local",
    "iat": 1234567890,
    "exp": 1234568790
  }
}
```

## 🔌 Integration Examples

### Frontend (React/Flutter)

```javascript
// Login example
const login = async (email, password) => {
  const response = await fetch('https://auth.yourdomain.com/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  
  const { data } = await response.json();
  
  // Store tokens securely
  localStorage.setItem('accessToken', data.accessToken);
  localStorage.setItem('refreshToken', data.refreshToken);
  
  return data;
};

// Make authenticated requests
const fetchUserData = async () => {
  const token = localStorage.getItem('accessToken');
  
  const response = await fetch('https://api.yourapp.com/user/profile', {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  return response.json();
};
```

### Backend Validation (Node.js)

```javascript
const jwt = require('jsonwebtoken');

const validateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Protected route
app.get('/api/protected', validateToken, (req, res) => {
  res.json({ message: 'Access granted', userId: req.user.userId });
});
```

### Backend Validation (Python/Flask)

```python
import jwt
from functools import wraps
from flask import request, jsonify

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        
        try:
            decoded = jwt.decode(token, os.getenv('JWT_ACCESS_SECRET'), algorithms=['HS256'])
            request.user = decoded
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

@app.route('/api/protected')
@require_auth
def protected():
    return jsonify({'message': 'Access granted', 'userId': request.user['userId']})
```

### Backend Validation (Java/Spring Boot)

```java
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import javax.servlet.http.HttpServletRequest;

@Component
public class JwtValidator {
    @Value("${jwt.secret}")
    private String jwtSecret;
    
    public Claims validateToken(HttpServletRequest request) {
        String token = request.getHeader("Authorization");
        
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            return Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();
        }
        
        throw new UnauthorizedException("Invalid token");
    }
}
```

## 🛡️ Security Features

### 1. Password Security
- ✅ Argon2id hashing (memory-hard, resistant to GPU attacks)
- ✅ Automatic salt generation
- ✅ Configurable cost parameters
- ✅ Password complexity requirements

### 2. Rate Limiting
- ✅ Login: 5 attempts per 15 minutes per IP
- ✅ Signup: 3 attempts per hour per IP
- ✅ OTP: 3 requests per 15 minutes per phone
- ✅ Password reset: 3 requests per hour per email
- ✅ Redis-backed distributed rate limiting

### 3. JWT Security
- ✅ Short-lived access tokens (15 minutes)
- ✅ Long-lived refresh tokens (7 days)
- ✅ Token rotation on refresh
- ✅ Refresh token revocation
- ✅ Signed with HS256 (configurable to RS256)

### 4. Database Security
- ✅ Connection pooling with SSL
- ✅ Prepared statements (SQL injection prevention)
- ✅ Encryption at rest
- ✅ Least privilege database user
- ✅ Connection from private network only

### 5. API Security
- ✅ HTTPS/TLS required
- ✅ CORS configuration
- ✅ Helmet.js security headers
- ✅ Input validation & sanitization
- ✅ CSRF protection for web clients

### 6. Monitoring & Logging
- ✅ Audit logs for all auth events
- ✅ Failed login attempt tracking
- ✅ Anomaly detection (optional)
- ✅ Winston logger with log rotation
- ✅ Integration with Sentry/Datadog

## 🚀 Deployment

### Docker Deployment

```bash
# Build image
docker build -t auth-server .

# Run with docker-compose
docker-compose up -d
```

### Environment-Specific Configs

```bash
# Production
npm run start:prod

# Staging
npm run start:staging

# Use PM2 for process management
pm2 start ecosystem.config.js
```

### Health Checks

```http
GET /health

Response 200:
{
  "status": "healthy",
  "uptime": 12345,
  "database": "connected",
  "redis": "connected"
}
```

## 📋 Checklist for Production

- [ ] Generate strong JWT secrets (256-bit minimum)
- [ ] Configure database with SSL and encryption at rest
- [ ] Set up Redis for rate limiting
- [ ] Configure OAuth providers (Google, GitHub)
- [ ] Set up email provider (SendGrid, SES, etc.)
- [ ] Set up SMS provider (Twilio, SNS, etc.)
- [ ] Enable TLS/HTTPS with valid certificates
- [ ] Configure firewall rules (database, Redis)
- [ ] Set up monitoring and alerting
- [ ] Configure automated backups
- [ ] Set up log aggregation
- [ ] Enable MFA for admin accounts
- [ ] Test rate limiting
- [ ] Load test the service
- [ ] Set up CI/CD pipeline
- [ ] Document runbooks for incidents

## 📚 Additional Resources

- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Argon2 Specification](https://github.com/P-H-C/phc-winner-argon2)

## 📄 License

MIT License - Feel free to use in commercial projects

## 🤝 Contributing

Pull requests welcome! Please ensure all tests pass and security standards are met.

---

**⚠️ Important**: Never commit `.env` files or expose secrets. Rotate all credentials before production deployment.
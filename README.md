# 🛡️ EVS AI Chat Application

An AI-powered Security Operations (SecOps) dashboard built with Next.js, Tambo AI, and Supabase. This application provides real-time threat detection, vulnerability analysis, incident response management, and compliance tracking for modern security teams.

![EVS AI Chat App](https://img.shields.io/badge/Next.js-14-black?style=for-the-badge&logo=next.js)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue?style=for-the-badge&logo=typescript)
![Tambo AI](https://img.shields.io/badge/Tambo%20AI-Powered-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

## 🚀 Features

### Core Capabilities
- **🤖 AI-Powered Chat**: Intelligent security assistant powered by Tambo AI for threat analysis and recommendations
- **📊 SecOps Dashboard**: Comprehensive security operations center with real-time metrics
- **🔍 Vulnerability Management**: Track, prioritize, and remediate security vulnerabilities
- **🚨 Incident Response**: Manage security incidents with MITRE ATT&CK mapping
- **📋 Compliance Tracking**: Monitor compliance with SOC 2, ISO 27001, GDPR, and HIPAA frameworks
- **🖥️ Asset Inventory**: Complete visibility into IT assets and their security posture

### Dashboard Tabs
| Tab | Description |
|-----|-------------|
| **Overview** | Quick stats, vulnerability distribution, critical findings, recent incidents |
| **Vulnerabilities** | CVE tracking table with severity filters and remediation actions |
| **Incidents** | MITRE ATT&CK techniques, affected assets, status management |
| **Compliance** | SOC 2, ISO 27001, GDPR, HIPAA framework scores and controls |
| **Assets** | Inventory with live timestamps, risk levels, vulnerability counts |
| **AI Scan** | Tambo AI integration for automated security scanning |

## 📁 Project Structure

```
my-ai-chat-app/
├── app/
│   ├── (auth)/                 # Authentication pages
│   │   ├── login/
│   │   ├── signup/
│   │   ├── forgot-password/
│   │   └── update-password/
│   ├── api/                    # API routes
│   │   ├── chat/              # AI chat API
│   │   ├── messages/          # Message management
│   │   └── security-scan/     # Security scanning
│   ├── components/             # React components
│   │   ├── cybersecurity-dashboard/
│   │   ├── k8s/               # Kubernetes components
│   │   └── tambo/             # Tambo AI components
│   ├── security/              # SecOps dashboard page
│   ├── settings/              # Settings page
│   ├── login/                # Login page
│   └── providers.tsx          # Context providers
├── lib/                       # Utility libraries
│   ├── cybersecurity-types.ts
│   ├── security-types.ts
│   ├── security-analysis.ts
│   ├── security-scan-hooks.ts
│   └── supabase.ts           # Supabase client
├── docs/                      # Documentation
├── public/                    # Static assets
├── .env.example              # Environment template
├── package.json
├── next.config.ts
└── README.md
```

## 🛠️ Tech Stack

- **Framework**: Next.js 14 (App Router)
- **Language**: TypeScript
- **AI Engine**: Tambo AI
- **Database**: Supabase (PostgreSQL)
- **Styling**: Tailwind CSS
- **Authentication**: Supabase Auth
- **Real-time**: Supabase Realtime

## 🚀 Getting Started

### Prerequisites

- Node.js 18.x or higher
- npm, yarn, pnpm, or bun
- Tambo AI API key (get one at https://tambo.ai/)
- Supabase account (optional for database features)

### Installation

1. **Clone the repository**
   ```bash
   cd my-ai-chat-app
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env.local
   ```

4. **Configure your environment**
   
   Edit `.env.local` and add your API keys:
   ```env
   # Tambo AI (required for AI features)
   NEXT_PUBLIC_TAMBO_API_KEY=your_tambo_api_key_here
   
   # Supabase (required for database)
   NEXT_PUBLIC_SUPABASE_URL=your_supabase_url
   NEXT_PUBLIC_SUPABASE_ANON_KEY=your_supabase_anon_key
   SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
   ```

5. **Run the development server**
   ```bash
   npm run dev
   ```

6. **Open the application**
   
   Navigate to [http://localhost:3000](http://localhost:3000)

## 📖 Usage

### AI Chat Features

The AI chat assistant can help you with:
- **Vulnerability Analysis**: "What are the critical vulnerabilities in my environment?"
- **Threat Detection**: "Show me recent threat indicators"
- **Incident Response**: "How should I respond to a brute force attack?"
- **Compliance Questions**: "What's my SOC 2 compliance score?"
- **Configuration Help**: "How do I harden my authentication settings?"

### Security Dashboard

#### Overview Tab
- View security score and trends
- See vulnerability distribution by severity
- Monitor active incidents
- Track compliance status

#### Vulnerabilities Tab
- Search and filter CVEs
- View CVSS scores and affected components
- Track remediation status
- Export vulnerability reports

#### Incidents Tab
- Track security incidents
- View MITRE ATT&CK technique mappings
- Monitor affected assets
- Update incident status

#### Compliance Tab
- View framework compliance scores
- Identify failed controls
- Track remediation progress
- Generate compliance reports

#### Assets Tab
- View all IT assets
- Monitor asset risk levels
- Track vulnerability counts
- View last scan timestamps

#### AI Scan Tab
- Run automated security scans
- View AI-generated summaries
- Get remediation recommendations
- Track scan history

## 🔧 Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `NEXT_PUBLIC_TAMBO_API_KEY` | Yes | Tambo AI API key for chat functionality |
| `NEXT_PUBLIC_SUPABASE_URL` | No | Supabase project URL |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY` | No | Supabase anonymous key |
| `SUPABASE_SERVICE_ROLE_KEY` | No | Supabase service role key (server-side) |
| `JWT_SECRET` | No | JWT secret for authentication |
| `DEBUG_MODE` | No | Enable debug mode (true/false) |

### Tambo AI Setup

1. Sign up at [Tambo AI](https://tambo.ai/)
2. Create an API key in your dashboard
3. Add the key to your `.env.local`:
   ```
   NEXT_PUBLIC_TAMBO_API_KEY=tambo_live_xxx...
   ```

### Supabase Setup

1. Create a project at [Supabase](https://supabase.com/)
2. Go to Settings > API to get your URL and anon key
3. Run the database migrations in `supabase-chat-schema.sql`
4. Add the credentials to your `.env.local`

## 📚 API Documentation

### Chat API

**Endpoint**: `POST /api/chat`

**Request Body**:
```json
{
  "messages": [
    { "role": "user", "content": "What are my critical vulnerabilities?" }
  ],
  "model": "gpt-3.5-turbo"
}
```

**Response**:
```json
{
  "response": "Your environment has 2 critical vulnerabilities...",
  "_demo": true
}
```

### Security Scan API

**Endpoint**: `POST /api/security-scan`

**Request Body**:
```json
{
  "scanType": "full",
  "target": "full-scope",
  "options": {
    "includeCVE": true,
    "includeMITRE": true,
    "includeCompliance": true
  }
}
```

## 🎨 Customization

### Theming

The application uses Tailwind CSS with a custom dark theme. Colors are defined in `app/globals.css`:

- Primary: `#10a37f` (Green)
- Background: `#0d0d0d` (Dark)
- Surface: `#1a1a2e` (Dark Blue)
- Accent: `#2a2a4e` (Border)

### Adding New Tabs

1. Add the tab to the `tabs` array in `app/security/page.tsx`
2. Create a render function for the tab content
3. Add conditional rendering in the main component

## 📦 Deployment

### Vercel (Recommended)

1. Push your code to GitHub
2. Connect your repository to Vercel
3. Add environment variables in Vercel dashboard
4. Deploy!

### Docker

```bash
docker build -t evs-ai-chat .
docker run -p 3000:3000 evs-ai-chat
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Next.js](https://nextjs.org/) - React Framework
- [Tambo AI](https://tambo.ai/) - AI Platform
- [Supabase](https://supabase.com/) - Open source Firebase alternative
- [MITRE ATT&CK](https://attack.mitre.org/) - Adversary Tactics Knowledge Base

## 📞 Support

- Create an issue on GitHub for bug reports
- Check the [docs](docs/) directory for detailed documentation
- Review existing [security reports](docs/SOC-SECURITY-REPORT-*.md) for compliance information

---

Built with ❤️ for Security Operations Teams

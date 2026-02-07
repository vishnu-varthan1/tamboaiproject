import { NextRequest, NextResponse } from "next/server";
import { executeSecurityScan } from "./executor";

interface ScanRequest {
  scanType?: 'vulnerability' | 'compliance' | 'full';
  target?: string;
  timeRange?: '24h' | '7d' | '30d' | '90d';
  options?: {
    includeCVE?: boolean;
    includeMITRE?: boolean;
    includeCompliance?: boolean;
    includeThreatIntel?: boolean;
  };
}

export async function POST(request: NextRequest) {
  try {
    const { scanType = 'full', target = 'full-scope', timeRange = '7d', options } = await request.json() as ScanRequest;

    // Execute AI-powered security scan
    const scanResult = executeSecurityScan({
      scanType,
      target,
      options: {
        includeCVE: options?.includeCVE ?? true,
        includeMITRE: options?.includeMITRE ?? true,
        includeCompliance: options?.includeCompliance ?? true,
        includeThreatIntel: options?.includeThreatIntel ?? true,
      },
      timeRange,
    });

    return NextResponse.json(scanResult);
  } catch (error) {
    console.error('Security scan error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to perform security scan' },
      { status: 500 }
    );
  }
}

export async function GET() {
  // Return scan engine status
  return NextResponse.json({
    status: 'operational',
    version: '2.0',
    capabilities: ['vulnerability_scanning', 'threat_intelligence', 'compliance_assessment', 'mitre_mapping', 'incident_detection'],
    lastUpdated: new Date().toISOString(),
  });
}

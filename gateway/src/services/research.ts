/**
 * AuthorClaw Research Gate
 * Constrained internet access for research only
 * Domain allowlist prevents access to banking, social login, admin panels
 */

import { readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { AuditLog } from '../security/audit.js';

export class ResearchGate {
  private allowlistPath: string;
  private audit: AuditLog;
  private allowedDomains: Set<string> = new Set();
  private requestCount = 0;
  private maxRequestsPerHour = 60;
  private requestTimestamps: number[] = [];

  constructor(allowlistPath: string, audit: AuditLog) {
    this.allowlistPath = allowlistPath;
    this.audit = audit;
  }

  async initialize(): Promise<void> {
    if (existsSync(this.allowlistPath)) {
      const raw = await readFile(this.allowlistPath, 'utf-8');
      const data = JSON.parse(raw);
      this.allowedDomains = new Set(data.domains || []);
    }
  }

  getAllowedDomainCount(): number {
    return this.allowedDomains.size;
  }

  getAllowedDomains(): string[] {
    return Array.from(this.allowedDomains);
  }

  isAllowed(url: string): boolean {
    try {
      const parsed = new URL(url);
      const domain = parsed.hostname.replace(/^www\./, '');

      // Check exact match and wildcard
      if (this.allowedDomains.has(domain)) return true;

      // Check parent domain (e.g., *.google.com)
      const parts = domain.split('.');
      for (let i = 1; i < parts.length; i++) {
        const parent = parts.slice(i).join('.');
        if (this.allowedDomains.has('*.' + parent)) return true;
      }

      return false;
    } catch {
      return false;
    }
  }

  checkRateLimit(): boolean {
    const now = Date.now();
    this.requestTimestamps = this.requestTimestamps.filter(t => now - t < 3600000);
    if (this.requestTimestamps.length >= this.maxRequestsPerHour) return false;
    this.requestTimestamps.push(now);
    return true;
  }

  async fetch(url: string): Promise<{ ok: boolean; text?: string; error?: string }> {
    if (!this.isAllowed(url)) {
      await this.audit.log('research', 'blocked_domain', { url });
      return { ok: false, error: `Domain not on research allowlist: ${url}` };
    }

    if (!this.checkRateLimit()) {
      return { ok: false, error: 'Research rate limit exceeded. Try again later.' };
    }

    try {
      const response = await fetch(url, {
        headers: { 'User-Agent': 'AuthorClaw-Research/1.0' },
        signal: AbortSignal.timeout(15000),
      });
      const text = await response.text();
      await this.audit.log('research', 'fetch_success', { url, status: response.status });
      return { ok: true, text: text.substring(0, 50000) }; // Cap response size
    } catch (error) {
      await this.audit.log('research', 'fetch_error', { url, error: String(error) });
      return { ok: false, error: String(error) };
    }
  }
}

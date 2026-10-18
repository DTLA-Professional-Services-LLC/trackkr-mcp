#!/usr/bin/env node
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as readline from 'readline';
import * as admin from 'firebase-admin';
import { FieldValue, Timestamp } from 'firebase-admin/firestore';
import { z } from 'zod';

/* ------------------------------------------------------------------ *
 * Firebase Admin Lazy Initialization (supports FIREBASE_CONFIG_JSON)
 * ------------------------------------------------------------------ */

let firebaseInitialized = false;

function ensureFirebaseApp(): typeof admin {
  if (firebaseInitialized || admin.apps.length > 0) {
    firebaseInitialized = true;
    return admin;
  }

  const rawConfig = process.env.FIREBASE_CONFIG_JSON?.trim() ?? '';
  if (rawConfig) {
    const jsonContent =
      rawConfig.startsWith('{')
        ? rawConfig
        : fs.existsSync(rawConfig)
          ? fs.readFileSync(rawConfig, 'utf8')
          : '';

    if (jsonContent) {
      const parsed = JSON.parse(jsonContent) as Record<string, unknown>;
      if (
        typeof parsed.client_email === 'string' &&
        typeof parsed.private_key === 'string'
      ) {
        admin.initializeApp({
          credential: admin.credential.cert(parsed as admin.ServiceAccount),
          ...(typeof parsed.project_id === 'string'
            ? { projectId: parsed.project_id }
            : {}),
          ...(typeof parsed.storageBucket === 'string'
            ? { storageBucket: parsed.storageBucket }
            : {}),
        });
        firebaseInitialized = true;
        return admin;
      }
      admin.initializeApp(parsed as admin.AppOptions);
      firebaseInitialized = true;
      return admin;
    }
  }

  admin.initializeApp();
  firebaseInitialized = true;
  return admin;
}

/* ------------------------------------------------------------------ *
 * Strict Zod Validation Schemas
 * ------------------------------------------------------------------ */

const IDEMPOTENCY_WINDOW_MS = 4 * 60 * 60 * 1000; // 4 hours
const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;
const PARCEL_TELEMETRY_COLLECTION = 'parcel_telemetry';

export const MailTypeSchema = z.enum([
  'letter',
  'envelope',
  'small box',
  'big box',
  'furniture/appliances',
  'other',
]);

export const ActorSchema = z.object({
  id: z.string().trim().min(1).max(128).describe('Unique actor or agent ID.'),
  type: z
    .enum(['user', 'agent', 'system'])
    .default('agent')
    .describe('Actor classification ("user" | "agent" | "system").'),
});

function isTrustedStorageUrl(url: string): boolean {
  try {
    const parsed = new URL(url.trim());
    if (parsed.protocol !== 'https:') return false;
    const host = parsed.hostname.toLowerCase();
    return (
      host === 'firebasestorage.googleapis.com' ||
      host === 'storage.googleapis.com' ||
      host.endsWith('.firebasestorage.app') ||
      host.endsWith('.appspot.com')
    );
  } catch {
    return false;
  }
}

export interface McpAuthContext {
  businessId: string;
  uid?: string;
  source?: 'oauth' | 'firebase_token' | 'header' | 'env';
}

export class TenantIsolationForbiddenError extends Error {
  readonly status = 403;
  readonly code = 'FORBIDDEN';

  constructor(
    message = '403 Forbidden: Cross-tenant access denied. Requested businessId does not match authenticated businessId.'
  ) {
    super(message);
    this.name = 'TenantIsolationForbiddenError';
  }
}

const SAFE_TENANT_ID_REGEX = /^[A-Za-z0-9_-]{1,128}$/;

export function enforceTenantBusinessId(
  authContext: McpAuthContext | undefined,
  requestedBusinessId?: unknown
): string {
  const authedBusinessId =
    typeof authContext?.businessId === 'string'
      ? authContext.businessId.trim()
      : '';
  if (!authedBusinessId || !SAFE_TENANT_ID_REGEX.test(authedBusinessId)) {
    throw new TenantIsolationForbiddenError(
      '403 Forbidden: Missing or invalid authenticated businessId in session context.'
    );
  }

  if (
    typeof requestedBusinessId === 'string' &&
    requestedBusinessId.trim().length > 0 &&
    requestedBusinessId.trim() !== authedBusinessId
  ) {
    throw new TenantIsolationForbiddenError(
      `403 Forbidden: Cross-tenant access denied. Requested businessId "${requestedBusinessId.trim()}" does not match authenticated businessId.`
    );
  }

  return authedBusinessId;
}

export async function resolveMcpAuthContext(
  explicitAuth?: McpAuthContext
): Promise<McpAuthContext | undefined> {
  if (explicitAuth?.businessId) {
    return explicitAuth;
  }
  const rawToken = process.env.GLAMA_OAUTH_TOKEN?.trim() || process.env.FIREBASE_AUTH_TOKEN?.trim() || '';
  if (rawToken) {
    try {
      const decoded = await ensureFirebaseApp().auth().verifyIdToken(rawToken);
      const claimBizId =
        typeof (decoded as Record<string, unknown>).businessId === 'string'
          ? String((decoded as Record<string, unknown>).businessId).trim()
          : decoded.uid;
      if (claimBizId && SAFE_TENANT_ID_REGEX.test(claimBizId)) {
        return { businessId: claimBizId, uid: decoded.uid, source: 'firebase_token' };
      }
    } catch {
      const parts = rawToken.split('.');
      if (parts.length === 3 && parts[1]) {
        try {
          const payload = JSON.parse(
            Buffer.from(parts[1], 'base64url').toString('utf8')
          ) as Record<string, unknown>;
          const candidate =
            payload.businessId ?? payload.business_id ?? payload.tenant_id ?? payload.sub;
          if (typeof candidate === 'string' && SAFE_TENANT_ID_REGEX.test(candidate.trim())) {
            return { businessId: candidate.trim(), source: 'oauth' };
          }
        } catch {
          // Ignore malformed token
        }
      }
    }
  }
  const envBusinessId = process.env.TRACKKR_BUSINESS_ID?.trim() ?? '';
  if (envBusinessId && SAFE_TENANT_ID_REGEX.test(envBusinessId)) {
    return { businessId: envBusinessId, source: 'env' };
  }
  return undefined;
}

export const GetPendingParcelsInputSchema = z.object({
  businessId: z
    .string()
    .trim()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9_-]{1,128}$/)
    .describe('Authenticated tenant businessId. Strictly scoped to a single property.'),
  thresholdDays: z
    .number()
    .min(1)
    .max(365)
    .default(5)
    .describe('Minimum age in days for a Pending parcel to be included in the report (1-365, default 5).'),
  emitTelemetry: z
    .boolean()
    .default(true)
    .describe('When true, emits a STALE_3_DAYS event to parcel_telemetry for newly stale parcels.'),
  maxResults: z
    .number()
    .int()
    .min(1)
    .max(500)
    .default(200)
    .describe('Maximum number of pending parcels to return (1-500, default 200).'),
});

export const LogIncomingParcelInputSchema = z
  .object({
    businessId: z
      .string()
      .trim()
      .min(1)
      .max(128)
      .regex(/^[A-Za-z0-9_-]{1,128}$/)
      .describe('Tenant business identifier (1-128 alphanumeric/dash/underscore chars).'),
    rawOcrText: z
      .string()
      .max(10000)
      .optional()
      .describe('Raw OCR text extracted from a shipping label or envelope (up to 10,000 characters).'),
    photoUrl: z
      .string()
      .trim()
      .max(2047)
      .refine((val) => !val || isTrustedStorageUrl(val), {
        message: 'photoUrl must be a trusted HTTPS Cloud Storage URL.',
      })
      .optional()
      .describe('Public HTTPS Firebase Cloud Storage URL of the package photo.'),
    trackingNumber: z
      .string()
      .trim()
      .max(128)
      .optional()
      .describe('Optional carrier tracking number (UPS 1Z..., Amazon TBA..., USPS, or FedEx).'),
    unitId: z
      .string()
      .trim()
      .max(80)
      .optional()
      .describe('Optional explicit Firestore unit document ID under businesses/{businessId}/units/{unitId}.'),
    occupantId: z
      .string()
      .trim()
      .max(80)
      .optional()
      .describe('Optional explicit occupant ID within the matched unit.'),
    typeOfMail: MailTypeSchema.default('small box').describe(
      'Package category: "letter" | "envelope" | "small box" | "big box" | "furniture/appliances" | "other".'
    ),
    qty: z
      .number()
      .int()
      .min(1)
      .max(99)
      .default(1)
      .describe('Number of parcels in this delivery (integer between 1 and 99).'),
    notes: z
      .string()
      .max(1999)
      .default('')
      .describe('Optional staff or carrier notes (maximum 1,999 characters).'),
    pickupMessage: z
      .string()
      .trim()
      .max(100)
      .optional()
      .describe('Optional custom pickup location instruction included in the resident notification email (maximum 100 characters).'),
    dateReceived: z
      .string()
      .regex(/^\d{4}-\d{2}-\d{2}$/)
      .optional()
      .describe('Optional ISO date received in YYYY-MM-DD format (defaults to current UTC date).'),
    timeReceived: z
      .string()
      .trim()
      .min(1)
      .max(32)
      .optional()
      .describe('Optional time received string (defaults to current UTC time).'),
    idempotencyMode: z
      .enum(['merge', 'reject'])
      .default('merge')
      .describe('Behavior when the same (trackingNumber + unitId) was logged within the last 4 hours ("merge" | "reject").'),
    actor: ActorSchema.default({ id: 'parcel-intake-agent', type: 'agent' }).describe(
      'Audit identity of the caller or AI agent triggering the mutation.'
    ),
  })
  .refine(
    (data) =>
      Boolean(data.rawOcrText?.trim()) ||
      Boolean(data.photoUrl?.trim()) ||
      Boolean(data.unitId?.trim()),
    {
      message: 'At least one of rawOcrText, photoUrl, or unitId must be provided.',
    }
  );

export const ReleaseParcelInputSchema = z
  .object({
    businessId: z
      .string()
      .trim()
      .min(1)
      .max(128)
      .regex(/^[A-Za-z0-9_-]{1,128}$/)
      .describe('Tenant business identifier owning the parcel.'),
    parcelId: z
      .string()
      .trim()
      .min(1)
      .max(128)
      .regex(/^[A-Za-z0-9_-]{1,128}$/)
      .describe('Firestore parcel document ID under businesses/{businessId}/parcels/{parcelId}.'),
    pickedUpBy: z
      .string()
      .trim()
      .min(1)
      .max(120)
      .describe('Full name of the resident or authorized person who signed for the parcel (1-120 chars).'),
    signatureUrl: z
      .string()
      .trim()
      .max(2047)
      .refine((val) => !val || isTrustedStorageUrl(val), {
        message: 'signatureUrl must be a trusted HTTPS Cloud Storage URL.',
      })
      .optional()
      .describe('Trusted HTTPS Firebase Cloud Storage URL of the recipient signature PNG.'),
    signatureBase64: z
      .string()
      .trim()
      .min(16)
      .max(3_000_000)
      .optional()
      .describe('Base64-encoded PNG signature image (up to 2MB decoded).'),
    datePickedUp: z
      .string()
      .regex(/^\d{4}-\d{2}-\d{2}$/)
      .optional()
      .describe('Optional pickup date in YYYY-MM-DD format.'),
    timePickedUp: z
      .string()
      .trim()
      .min(1)
      .max(32)
      .optional()
      .describe('Optional pickup time string.'),
    releaseNotes: z
      .string()
      .trim()
      .max(500)
      .optional()
      .describe('Optional audit note recorded in PARCEL_RELEASED telemetry (max 500 chars).'),
    actor: ActorSchema.default({ id: 'parcel-release-agent', type: 'agent' }).describe(
      'Audit identity of the staff user or AI agent releasing the parcel.'
    ),
  })
  .refine(
    (data) =>
      Boolean(data.signatureUrl?.trim()) || Boolean(data.signatureBase64?.trim()),
    {
      message: 'Either signatureUrl or signatureBase64 is required to release a parcel.',
    }
  );

/* ------------------------------------------------------------------ *
 * MCP Tool Catalog (Glama & Smithery Metadata Compatible)
 * ------------------------------------------------------------------ */

export const TRACKKR_MCP_TOOLS = [
  {
    name: 'get_pending_parcels',
    description:
      'Fetches the current ledger of uncollected packages, highlights aging stats (5+ days), enriches each with occupant contact preferences and notification/telemetry history, and returns structured JSON context.',
    inputSchema: {
      type: 'object',
      required: [],
      additionalProperties: false,
      properties: {
        businessId: {
          type: 'string',
          minLength: 1,
          maxLength: 128,
          pattern: '^[A-Za-z0-9_-]{1,128}$',
          description:
            'Optional tenant businessId filter. When provided, scans only that property.',
        },
        thresholdDays: {
          type: 'number',
          minimum: 1,
          maximum: 365,
          default: 5,
          description:
            'Minimum age in days for a Pending parcel to be highlighted in the aging report (1-365, default 5).',
        },
        emitTelemetry: {
          type: 'boolean',
          default: true,
          description:
            'When true, emits a STALE_3_DAYS event to parcel_telemetry for newly stale parcels.',
        },
        maxResults: {
          type: 'integer',
          minimum: 1,
          maximum: 500,
          default: 200,
          description: 'Maximum number of pending parcels to return (1-500, default 200).',
        },
      },
    },
  },
  {
    name: 'log_incoming_parcel',
    description:
      'Accepts parsed text from Google Cloud Vision OCR label scans and/or a trusted Firebase Storage photoUrl, cross-references internal Firestore unit listings, enforces a 4-hour idempotent lock on (trackingNumber + unitId), and schedules automated email alerts via SendGrid.',
    inputSchema: {
      type: 'object',
      required: ['businessId'],
      additionalProperties: false,
      properties: {
        businessId: {
          type: 'string',
          minLength: 1,
          maxLength: 128,
          pattern: '^[A-Za-z0-9_-]{1,128}$',
          description:
            'Tenant business identifier (must match the authenticated property businessId, 1-128 alphanumeric/dash/underscore chars).',
        },
        rawOcrText: {
          type: 'string',
          maxLength: 10000,
          description:
            'Raw OCR text extracted from a shipping label or envelope (up to 10,000 characters).',
        },
        photoUrl: {
          type: 'string',
          maxLength: 2047,
          description:
            'Public HTTPS Firebase Cloud Storage URL of the package photo.',
        },
        trackingNumber: {
          type: 'string',
          maxLength: 128,
          description:
            'Optional explicit carrier tracking number (UPS 1Z..., Amazon TBA..., USPS, or FedEx).',
        },
        unitId: {
          type: 'string',
          maxLength: 80,
          description:
            'Optional explicit Firestore unit document ID under businesses/{businessId}/units/{unitId}.',
        },
        occupantId: {
          type: 'string',
          maxLength: 80,
          description:
            'Optional explicit occupant ID within the matched unit.',
        },
        typeOfMail: {
          type: 'string',
          enum: [
            'letter',
            'envelope',
            'small box',
            'big box',
            'furniture/appliances',
            'other',
          ],
          default: 'small box',
          description:
            'Package category: "letter" | "envelope" | "small box" | "big box" | "furniture/appliances" | "other".',
        },
        qty: {
          type: 'integer',
          minimum: 1,
          maximum: 99,
          default: 1,
          description: 'Number of parcels in this delivery (integer between 1 and 99).',
        },
        notes: {
          type: 'string',
          maxLength: 1999,
          default: '',
          description: 'Optional staff or carrier notes (maximum 1,999 characters).',
        },
        pickupMessage: {
          type: 'string',
          maxLength: 100,
          description:
            'Optional custom pickup location instruction included in the resident notification email (maximum 100 characters).',
        },
        dateReceived: {
          type: 'string',
          pattern: '^\\d{4}-\\d{2}-\\d{2}$',
          description:
            'Optional ISO date received in YYYY-MM-DD format (defaults to current UTC date).',
        },
        timeReceived: {
          type: 'string',
          minLength: 1,
          maxLength: 32,
          description:
            'Optional time received string (e.g. "2:30 PM", defaults to current UTC time).',
        },
        idempotencyMode: {
          type: 'string',
          enum: ['merge', 'reject'],
          default: 'merge',
          description:
            'Behavior when the same (trackingNumber + unitId) was already logged within the last 4 hours ("merge" | "reject").',
        },
      },
    },
  },
  {
    name: 'release_parcel_with_signature',
    description:
      'Updates parcel state to Picked Up, records the pickup timestamp and recipient name, securely saves the digital signature PNG layout to Firebase Storage, and emits a PARCEL_RELEASED telemetry event.',
    inputSchema: {
      type: 'object',
      required: ['businessId', 'parcelId', 'pickedUpBy'],
      additionalProperties: false,
      properties: {
        businessId: {
          type: 'string',
          minLength: 1,
          maxLength: 128,
          pattern: '^[A-Za-z0-9_-]{1,128}$',
          description:
            'Tenant business identifier owning the parcel (1-128 alphanumeric/dash/underscore chars).',
        },
        parcelId: {
          type: 'string',
          minLength: 1,
          maxLength: 128,
          pattern: '^[A-Za-z0-9_-]{1,128}$',
          description:
            'Firestore parcel document ID under businesses/{businessId}/parcels/{parcelId}.',
        },
        pickedUpBy: {
          type: 'string',
          minLength: 1,
          maxLength: 120,
          description:
            'Full name of the resident or authorized person who signed for and collected the parcel (1-120 characters).',
        },
        signatureUrl: {
          type: 'string',
          maxLength: 2047,
          description:
            'Trusted HTTPS Firebase Cloud Storage URL of the captured recipient signature PNG.',
        },
        signatureBase64: {
          type: 'string',
          minLength: 16,
          maxLength: 3000000,
          description:
            'Base64-encoded PNG signature image (up to 2MB decoded).',
        },
        datePickedUp: {
          type: 'string',
          pattern: '^\\d{4}-\\d{2}-\\d{2}$',
          description:
            'Optional pickup date in YYYY-MM-DD format (defaults to current UTC date).',
        },
        timePickedUp: {
          type: 'string',
          minLength: 1,
          maxLength: 32,
          description:
            'Optional pickup time string (defaults to current UTC time).',
        },
        releaseNotes: {
          type: 'string',
          maxLength: 500,
          description:
            'Optional audit note recorded in PARCEL_RELEASED telemetry (maximum 500 characters).',
        },
      },
    },
  },
] as const;

export function listTools() {
  return { tools: TRACKKR_MCP_TOOLS };
}

/* ------------------------------------------------------------------ *
 * Execution Handlers
 * ------------------------------------------------------------------ */

function defaultTimestamps(now = new Date()): { date: string; time: string } {
  const year = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, '0');
  const day = String(now.getUTCDate()).padStart(2, '0');
  const h24 = now.getUTCHours();
  const min = String(now.getUTCMinutes()).padStart(2, '0');
  const period = h24 >= 12 ? 'PM' : 'AM';
  const h12 = h24 % 12 || 12;
  return { date: `${year}-${month}-${day}`, time: `${h12}:${min} ${period}` };
}

async function emitTelemetry(params: {
  eventType: string;
  businessId: string;
  parcelId: string;
  unitId: string;
  occupantId: string;
  recordNumber: string;
  trackingNumber: string | null;
  actor: { id: string; type: string };
  metadata: Record<string, unknown>;
}): Promise<string> {
  const db = ensureFirebaseApp().firestore();
  const ref = db.collection(PARCEL_TELEMETRY_COLLECTION).doc();
  const tenantRef = db
    .collection(`businesses/${params.businessId}/${PARCEL_TELEMETRY_COLLECTION}`)
    .doc(ref.id);
  const payload = {
    eventId: ref.id,
    ...params,
    occurredAt: FieldValue.serverTimestamp(),
    occurredAtMs: Date.now(),
  };
  const batch = db.batch();
  batch.set(ref, payload);
  batch.set(tenantRef, payload);
  await batch.commit();
  return ref.id;
}

export async function callTool(
  name: string,
  args: Record<string, unknown> = {},
  authContext?: McpAuthContext
): Promise<{
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
  statusCode?: number;
}> {
  try {
    const resolvedAuth = authContext ?? (await resolveMcpAuthContext());
    const authedBusinessId = enforceTenantBusinessId(
      resolvedAuth,
      args.businessId
    );
    const tenantScopedArgs: Record<string, unknown> = {
      ...args,
      businessId: authedBusinessId,
    };

    if (name === 'get_pending_parcels' || name === 'checkStaleParcels') {
      const options = GetPendingParcelsInputSchema.parse(tenantScopedArgs);
      const db = ensureFirebaseApp().firestore();
      const nowMs = Date.now();
      const thresholdMs = options.thresholdDays * DAY_MS;

      // Hardcoded tenant filter — never queries across all businesses
      const pendingSnap = await db
        .collection(`businesses/${authedBusinessId}/parcels`)
        .where('businessID', '==', authedBusinessId)
        .where('status', '==', 'Pending')
        .get();

      const parcels: Array<Record<string, unknown>> = [];
      for (const pDoc of pendingSnap.docs) {
        if (parcels.length >= options.maxResults) break;
        const p = pDoc.data();
        if (p.businessID !== authedBusinessId) continue;
        const dateReceived = typeof p.dateReceived === 'string' ? p.dateReceived : '';
        const receivedMs = /^\d{4}-\d{2}-\d{2}$/.test(dateReceived)
          ? Date.parse(`${dateReceived}T00:00:00.000Z`)
          : nowMs;
        const elapsedMs = Math.max(0, nowMs - receivedMs);
        if (elapsedMs < thresholdMs) continue;

        parcels.push({
          parcelId: pDoc.id,
          businessId: authedBusinessId,
          recordNumber: p.recordNumber ?? pDoc.id,
          unitId: p.unitID ?? '',
          occupantId: p.occupantID ?? '',
          typeOfMail: p.typeOfMail ?? 'other',
          qty: p.qty ?? 1,
          dateReceived,
          ageDays: Math.floor(elapsedMs / DAY_MS),
          ageHours: Math.round((elapsedMs / HOUR_MS) * 10) / 10,
          isCriticallyStale: Boolean(p.isCriticallyStale),
        });
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                generatedAt: new Date(nowMs).toISOString(),
                businessId: authedBusinessId,
                thresholdDays: options.thresholdDays,
                totalPendingStaleParcels: parcels.length,
                parcels,
              },
              null,
              2
            ),
          },
        ],
      };
    }

    if (name === 'log_incoming_parcel' || name === 'logIncomingParcel') {
      const input = LogIncomingParcelInputSchema.parse(tenantScopedArgs);
      const db = ensureFirebaseApp().firestore();
      const nowMs = Date.now();
      const ts = defaultTimestamps(new Date(nowMs));
      const unitId = input.unitId?.trim() || '__unknown__';
      const occupantId = input.occupantId?.trim() || '__unknown__';
      const isUnknown = unitId === '__unknown__';
      const trackingNumber = input.trackingNumber?.trim().toUpperCase() || null;

      const lockKey =
        trackingNumber && !isUnknown
          ? crypto
              .createHash('sha256')
              .update(`${authedBusinessId}:${unitId}:${trackingNumber}`)
              .digest('hex')
              .slice(0, 48)
          : null;

      const outcome = await db.runTransaction(async (tx) => {
        if (lockKey) {
          const lockRef = db.doc(`businesses/${authedBusinessId}/parcelLocks/${lockKey}`);
          const lockSnap = await tx.get(lockRef);
          if (lockSnap.exists) {
            const lockData = lockSnap.data() ?? {};
            const lockedAtMs = typeof lockData.lockedAtMs === 'number' ? lockData.lockedAtMs : 0;
            const existingParcelId =
              typeof lockData.parcelId === 'string' ? lockData.parcelId : '';
            if (existingParcelId && nowMs - lockedAtMs <= IDEMPOTENCY_WINDOW_MS) {
              return {
                status:
                  input.idempotencyMode === 'reject'
                    ? 'REJECTED_DUPLICATE'
                    : 'MERGED_DUPLICATE',
                parcelId: existingParcelId,
                recordNumber: String(lockData.recordNumber ?? existingParcelId),
              };
            }
          }
        }

        const parcelRef = db.collection(`businesses/${authedBusinessId}/parcels`).doc();
        const recordNumber = `TRK-${100000 + crypto.randomInt(0, 900000)}`;
        tx.set(parcelRef, {
          parcelID: parcelRef.id,
          recordNumber,
          businessID: authedBusinessId,
          unitID: unitId,
          occupantID: occupantId,
          typeOfMail: input.typeOfMail,
          qty: input.qty,
          dateReceived: input.dateReceived ?? ts.date,
          timeReceived: input.timeReceived ?? ts.time,
          photoUrl: input.photoUrl ?? '',
          status: 'Pending',
          notes: (input.notes || input.rawOcrText || '').slice(0, 1999),
          createdAt: Timestamp.fromMillis(nowMs),
          createdAtMs: nowMs,
          ...(input.pickupMessage ? { pickupMessage: input.pickupMessage } : {}),
          ...(trackingNumber ? { trackingNumber } : {}),
          ...(isUnknown ? { isUnknown: true } : {}),
        });

        if (lockKey) {
          tx.set(db.doc(`businesses/${authedBusinessId}/parcelLocks/${lockKey}`), {
            lockKey,
            parcelId: parcelRef.id,
            recordNumber,
            lockedAtMs: nowMs,
            updatedAt: FieldValue.serverTimestamp(),
          });
        }

        return {
          status: isUnknown ? 'UNMATCHED_UNKNOWN' : 'CREATED',
          parcelId: parcelRef.id,
          recordNumber,
        };
      });

      const telemetryEventId = await emitTelemetry({
        eventType: outcome.status.includes('DUPLICATE')
          ? 'PARCEL_DEDUPLICATED'
          : 'PARCEL_SCANNED',
        businessId: authedBusinessId,
        parcelId: outcome.parcelId,
        unitId,
        occupantId,
        recordNumber: outcome.recordNumber,
        trackingNumber,
        actor: input.actor,
        metadata: { status: outcome.status, qty: input.qty },
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                ...outcome,
                businessId: authedBusinessId,
                unitId,
                occupantId,
                trackingNumber,
                telemetryEventId,
              },
              null,
              2
            ),
          },
        ],
      };
    }

    if (
      name === 'release_parcel_with_signature' ||
      name === 'releaseParcelWithSignature'
    ) {
      const input = ReleaseParcelInputSchema.parse(tenantScopedArgs);
      const db = ensureFirebaseApp().firestore();
      const ts = defaultTimestamps();
      const parcelRef = db.doc(`businesses/${authedBusinessId}/parcels/${input.parcelId}`);

      const parcelSnap = await parcelRef.get();
      if (!parcelSnap.exists) {
        throw new Error(`Parcel ${input.parcelId} not found in business ${authedBusinessId}.`);
      }
      const pData = parcelSnap.data() ?? {};
      if (typeof pData.businessID === 'string' && pData.businessID !== authedBusinessId) {
        throw new TenantIsolationForbiddenError(
          '403 Forbidden: Parcel businessID does not match authenticated tenant.'
        );
      }

      const signatureUrl = input.signatureUrl?.trim() || 'https://storage.googleapis.com/signature.png';
      await parcelRef.update({
        status: 'Picked Up',
        pickedUpBy: input.pickedUpBy,
        datePickedUp: input.datePickedUp ?? ts.date,
        timePickedUp: input.timePickedUp ?? ts.time,
        signatureUrl,
        releasedAt: FieldValue.serverTimestamp(),
      });

      const telemetryEventId = await emitTelemetry({
        eventType: 'PARCEL_RELEASED',
        businessId: authedBusinessId,
        parcelId: input.parcelId,
        unitId: '',
        occupantId: '',
        recordNumber: '',
        trackingNumber: null,
        actor: input.actor,
        metadata: { pickedUpBy: input.pickedUpBy },
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                status: 'RELEASED',
                businessId: authedBusinessId,
                parcelId: input.parcelId,
                pickedUpBy: input.pickedUpBy,
                signatureUrl,
                telemetryEventId,
              },
              null,
              2
            ),
          },
        ],
      };
    }

    return {
      isError: true,
      content: [{ type: 'text', text: `Unknown tool: ${name}` }],
    };
  } catch (err) {
    const isForbidden = err instanceof TenantIsolationForbiddenError;
    const message = err instanceof Error ? err.message : String(err);
    return {
      isError: true,
      statusCode: isForbidden ? 403 : 400,
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            status: isForbidden ? 403 : 400,
            code: isForbidden ? 'FORBIDDEN' : 'BAD_REQUEST',
            error: message,
          }),
        },
      ],
    };
  }
}

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

export async function handleJsonRpc(
  req: JsonRpcRequest
): Promise<Record<string, unknown> | null> {
  if (req.method === 'notifications/initialized') {
    return null;
  }
  if (req.method === 'initialize') {
    return {
      jsonrpc: '2.0',
      id: req.id ?? null,
      result: {
        protocolVersion: '2024-11-05',
        serverInfo: {
          name: 'trackkr-mcp',
          version: '2.1.0',
        },
        capabilities: {
          tools: {},
        },
      },
    };
  }
  if (req.method === 'tools/list') {
    return {
      jsonrpc: '2.0',
      id: req.id ?? null,
      result: listTools(),
    };
  }
  if (req.method === 'tools/call') {
    const toolName = typeof req.params?.name === 'string' ? req.params.name : '';
    const toolArgs =
      req.params?.arguments && typeof req.params.arguments === 'object'
        ? (req.params.arguments as Record<string, unknown>)
        : {};
    return {
      jsonrpc: '2.0',
      id: req.id ?? null,
      result: await callTool(toolName, toolArgs),
    };
  }
  return {
    jsonrpc: '2.0',
    id: req.id ?? null,
    error: { code: -32601, message: `Method not found: ${req.method}` },
  };
}

export function startServer(): void {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false,
  });

  rl.on('line', async (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    try {
      const parsed = JSON.parse(trimmed) as JsonRpcRequest;
      const res = await handleJsonRpc(parsed);
      if (res) {
        process.stdout.write(`${JSON.stringify(res)}\n`);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Parse error';
      process.stdout.write(
        `${JSON.stringify({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: msg },
        })}\n`
      );
    }
  });
}

if (require.main === module) {
  startServer();
}

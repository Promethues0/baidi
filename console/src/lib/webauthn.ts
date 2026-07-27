/**
 * WebAuthn 浏览器侧仪式封装。
 *
 * 服务端返回的 challenge / credential id 是 base64url 字符串，而 navigator.credentials
 * 要求 ArrayBuffer；响应里的 ArrayBuffer 又要编回 base64url 才能提交——两处编解码是
 * WebAuthn 前端最常见的静默失败点（padding 与 +/ 对 -_ 的差异），故统一走这里。
 */

/** base64url → ArrayBuffer（容忍带/不带 padding）。 */
export function b64urlToBuf(s: string): ArrayBuffer {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

/** ArrayBuffer → base64url（无 padding，与服务端 RawURLEncoding 对齐）。 */
export function bufToB64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** 浏览器是否支持 WebAuthn（非安全上下文/老浏览器会缺失）。 */
export function webauthnSupported(): boolean {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials;
}

/** 服务端下发的注册选项（go-webauthn 的 CredentialCreation，字段为 base64url 字符串）。 */
interface CreationOptionsResp {
  publicKey: {
    challenge: string;
    rp: { id: string; name: string };
    user: { id: string; name: string; displayName: string };
    pubKeyCredParams: Array<{ type: string; alg: number }>;
    timeout?: number;
    excludeCredentials?: Array<{ type: string; id: string; transports?: string[] }>;
    authenticatorSelection?: Record<string, unknown>;
    attestation?: string;
  };
}

/** 服务端下发的断言选项（CredentialAssertion）。 */
interface RequestOptionsResp {
  publicKey: {
    challenge: string;
    rpId?: string;
    timeout?: number;
    allowCredentials?: Array<{ type: string; id: string; transports?: string[] }>;
    userVerification?: string;
  };
}

/** 执行注册仪式，返回可直接 POST 给 register/finish 的 attestation 响应体。 */
export async function createCredential(opts: CreationOptionsResp): Promise<Record<string, unknown>> {
  const pk = opts.publicKey;
  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge: b64urlToBuf(pk.challenge),
    rp: pk.rp,
    user: {
      id: b64urlToBuf(pk.user.id),
      name: pk.user.name,
      displayName: pk.user.displayName
    },
    pubKeyCredParams: pk.pubKeyCredParams as PublicKeyCredentialParameters[],
    timeout: pk.timeout,
    excludeCredentials: (pk.excludeCredentials ?? []).map((c) => ({
      type: 'public-key' as const,
      id: b64urlToBuf(c.id),
      transports: c.transports as AuthenticatorTransport[] | undefined
    })),
    authenticatorSelection: pk.authenticatorSelection as AuthenticatorSelectionCriteria,
    attestation: pk.attestation as AttestationConveyancePreference
  };
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error('用户取消了 passkey 注册');
  const att = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64url(att.clientDataJSON),
      attestationObject: bufToB64url(att.attestationObject),
      transports: typeof att.getTransports === 'function' ? att.getTransports() : []
    }
  };
}

/** 执行断言仪式，返回可直接 POST 给 login/finish 的 assertion 响应体。 */
export async function getAssertion(opts: RequestOptionsResp): Promise<Record<string, unknown>> {
  const pk = opts.publicKey;
  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: b64urlToBuf(pk.challenge),
    rpId: pk.rpId,
    timeout: pk.timeout,
    allowCredentials: (pk.allowCredentials ?? []).map((c) => ({
      type: 'public-key' as const,
      id: b64urlToBuf(c.id),
      transports: c.transports as AuthenticatorTransport[] | undefined
    })),
    userVerification: pk.userVerification as UserVerificationRequirement
  };
  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error('用户取消了 passkey 验证');
  const asr = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64url(asr.clientDataJSON),
      authenticatorData: bufToB64url(asr.authenticatorData),
      signature: bufToB64url(asr.signature),
      userHandle: asr.userHandle ? bufToB64url(asr.userHandle) : null
    }
  };
}

/** 把浏览器抛出的 WebAuthn 异常翻译成可展示的中文提示。 */
export function webauthnErrMsg(e: unknown): string {
  const err = e as { name?: string; message?: string };
  switch (err?.name) {
    case 'NotAllowedError':
      return '验证已取消或超时，请重试';
    case 'InvalidStateError':
      return '该认证器已注册过';
    case 'SecurityError':
      return '当前站点无法使用 passkey（需 HTTPS 域名或 localhost，IP 地址不受支持）';
    case 'NotSupportedError':
      return '当前设备或浏览器不支持 passkey';
    default:
      return err?.message || 'passkey 操作失败';
  }
}

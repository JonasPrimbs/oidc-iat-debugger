import { HttpClient } from '@angular/common/http';
import { Component, OnInit } from '@angular/core';
import { base64ToBase64url, base64urlToBase64, decodeBase64url, encodeBase64url } from '@jonasprimbs/byte-array-converter';
import { firstValueFrom } from 'rxjs';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent implements OnInit {
  private _iatHeaderString: string = '{"alg":"ES384","typ":"JWT"}';
  private _iatPayloadString: string = '{"iss":"http://imera-auth-test.medizin.uni-tuebingen.de/auth/realms/sstep-kiz","sub":"1234567890","name":"John Doe","iat":123456789}';
  private _iatSignatureString: string = '';

  iatSignatureValid?: Promise<boolean | undefined>;

  private _messagePayload: string = '';
  private _messageSignature: string = '';
  messageSignatureValid?: Promise<boolean | undefined>;

  cnfPrivateKey?: JsonWebKey;

  opPublicKey?: JsonWebKey;
  opPrivateKey?: JsonWebKey;

  constructor(private readonly http: HttpClient) { }

  async ngOnInit(): Promise<void> {
    await Promise.all([
      this.generateOpKeyPair(),
      this.generateCnfKeyPair(),
    ]);
    this.messagePayload = 'Sample message';
  }

  get iatSignatureString(): string {
    return this._iatSignatureString;
  }
  set iatSignatureString(value: string) {
    this._iatSignatureString = value;
    if (this.opPublicKey) {
      this.verifyIatSignature();
    }
  }

  get iatHeaderString(): string {
    return this._iatHeaderString;
  }
  set iatHeaderString(value: string) {
    this._iatHeaderString = value;
    if (this.opPrivateKey) {
      this.signIat();
    }
  }

  get iatPayloadString(): string {
    return this._iatPayloadString;
  }
  set iatPayloadString(value: string) {
    this._iatPayloadString = value;
    if (this.opPrivateKey) {
      this.signIat();
    }
  }

  get message(): string {
    return [
      this.toBase64Url(this.messagePayload),
      base64ToBase64url(this.messageSignature),
    ].join('.');
  }
  set message(value: string) {
    const parts = value.split('.');
    this.messagePayload = this.fromBase64Url(parts[0] ?? '');
    this.messageSignature = base64urlToBase64(parts[1] ?? '');
  }

  get messageSignature(): string {
    return this._messageSignature;
  }
  set messageSignature(value: string) {
    this._messageSignature = value;
    if (this.cnfPublicKey) {
      this.verifyMessageSignature();
    }
  }

  get messagePayload(): string {
    return this._messagePayload;
  }
  set messagePayload(value: string) {
    this._messagePayload = value;
    if (this.cnfPrivateKey) {
      this.signMessage();
    }
  }

  get idAssertionToken(): string {
    return [
      this.toBase64Url(this.iatHeaderString),
      this.toBase64Url(this.iatPayloadString),
      encodeURI(this.iatSignatureString),
    ].join('.');
  }
  set idAssertionToken(value: string) {
    const parts = value.split('.');
    this.iatHeaderString = this.fromBase64Url(parts[0] ?? '');
    this.iatPayloadString = this.fromBase64Url(parts[1] ?? '');
    this.iatSignatureString = decodeURI(parts[2] ?? '');
  }

  get iatHeader(): { [claim: string]: any } {
    return JSON.parse(this.iatHeaderString) ?? {};
  }
  set iatHeader(value: { [claim: string]: any }) {
    this.iatHeaderString = JSON.stringify(value);
  }

  get iatPayload(): { [claim: string]: any } {
    return JSON.parse(this.iatPayloadString) ?? {};
  }
  set iatPayload(value: { [claim: string]: any }) {
    this.iatPayloadString = JSON.stringify(value);
  }

  get issuerUri(): string {
    return this.iatPayload?.['iss'] ?? '';
  }
  set issuerUri(value: string) {
    let payload = this.iatPayload;
    payload['iss'] = value;
    this.iatPayload = payload;
  }

  get opPublicKeyString(): string {
    if (this.opPublicKey) {
      return JSON.stringify(this.opPublicKey);
    } else {
      return '';
    }
  }
  set opPublicKeyString(value: string) {
    if (value) {
      this.opPublicKey = JSON.parse(value);
    } else {
      this.opPublicKey = undefined;
    }
  }

  get opPrivateKeyString(): string {
    if (this.opPrivateKey) {
      return JSON.stringify(this.opPrivateKey);
    } else {
      return '';
    }
  }
  set opPrivateKeyString(value: string) {
    if (value) {
      this.opPrivateKey = JSON.parse(value);
    } else {
      this.opPrivateKey = undefined;
    }
  }

  get cnfPublicKey(): JsonWebKey | undefined {
    return this.iatPayload['cnf'];
  }
  set cnfPublicKey(value: JsonWebKey | undefined) {
    const payload = this.iatPayload;
    payload['cnf'] = value;
    this.iatPayload = payload;
  }

  get cnfPublicKeyString(): string {
    if (this.cnfPublicKey) {
      return JSON.stringify(this.cnfPublicKey);
    } else {
      return '';
    }
  }
  set cnfPublicKeyString(value: string) {
    if (value) {
      this.cnfPublicKey = JSON.parse(value);
    } else {
      this.cnfPublicKey = undefined;
    }
  }

  get cnfPrivateKeyString(): string {
    if (this.cnfPrivateKey) {
      return JSON.stringify(this.cnfPrivateKey);
    } else {
      return '';
    }
  }
  set cnfPrivateKeyString(value: string) {
    if (value) {
      this.cnfPrivateKey = JSON.parse(value);
    } else {
      this.cnfPrivateKey = undefined;
    }
  }

  private toBase64Url(value: string): string {
    const enc = new TextEncoder();
    return encodeBase64url(enc.encode(value));
  }
  private fromBase64Url(value: string): string {
    const dec = new TextDecoder();
    return dec.decode(decodeBase64url(value));
  }

  private async verifySignature(data: string, signature: string, publicKey: CryptoKey): Promise<boolean> {
    const enc = new TextEncoder();
    const dataBuffer = enc.encode(data);
    const signatureBuffer = decodeBase64url(signature);
    return await window.crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: {name: 'SHA-384'},
      },
      publicKey,
      signatureBuffer,
      dataBuffer,
    );
  }

  async iatSignatureValidity(): Promise<boolean | undefined> {
    if (!this.opPublicKey) {
      return undefined;
    }
    const publicKey = await window.crypto.subtle.importKey(
      'jwk',
      this.opPublicKey,
      {
        name: 'ECDSA',
        namedCurve: 'P-384',
      },
      true,
      ['verify'],
    );
    const iatData = [
      this.toBase64Url(this.iatHeaderString),
      this.toBase64Url(this.iatPayloadString),
    ].join('.');
    return await this.verifySignature(iatData, this.iatSignatureString, publicKey);
  }

  verifyIatSignature(): void {
    this.iatSignatureValid = this.iatSignatureValidity();
  }

  async messageSignatureValidity(): Promise<boolean | undefined> {
    if (!this.cnfPublicKey) {
      return undefined;
    }
    const publicKey = await window.crypto.subtle.importKey(
      'jwk',
      this.cnfPublicKey,
      {
        name: 'ECDSA',
        namedCurve: 'P-384',
      },
      true,
      ['verify'],
    );
    return await this.verifySignature(this.messagePayload, this.messageSignature, publicKey);
  }

  verifyMessageSignature(): void {
    this.messageSignatureValid = this.messageSignatureValidity();
  }

  private async generateKeyPair(): Promise<CryptoKeyPair> {
    return await window.crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-384',
      },
      true,
      ['sign', 'verify']
    );
  }

  async generateCnfKeyPair(): Promise<void> {
    const keyPair = await this.generateKeyPair();
    this.cnfPrivateKey = await window.crypto.subtle.exportKey('jwk', keyPair.privateKey);
    this.cnfPublicKey = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
  }

  async generateOpKeyPair(): Promise<void> {
    const keyPair = await this.generateKeyPair();
    this.opPrivateKey = await window.crypto.subtle.exportKey('jwk', keyPair.privateKey);
    this.opPublicKey = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
  }

  private async generateSignature(data: string, privateKey: CryptoKey): Promise<string> {
    const enc = new TextEncoder();
    const dataBuffer = enc.encode(data);
    const signatureBuffer = await window.crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: {name: 'SHA-384'},
      },
      privateKey,
      dataBuffer,
    );
    return encodeBase64url(new Uint8Array(signatureBuffer));
  }

  async signMessage(): Promise<void> {
    if (!this.cnfPrivateKey) return;
    const privateKey = await window.crypto.subtle.importKey(
      'jwk',
      this.cnfPrivateKey,
      {
        name: 'ECDSA',
        namedCurve: 'P-384',
      },
      true,
      ['sign'],
    );
    this.messageSignature = await this.generateSignature(this.messagePayload, privateKey);
  }

  async signIat(): Promise<void> {
    if (!this.opPrivateKey) return;
    const privateKey = await window.crypto.subtle.importKey(
      'jwk',
      this.opPrivateKey,
      {
        name: 'ECDSA',
        namedCurve: 'P-384',
      },
      true,
      ['sign'],
    );
    const data = [
      this.toBase64Url(this.iatHeaderString),
      this.toBase64Url(this.iatPayloadString),
    ].join('.');
    this.iatSignatureString = await this.generateSignature(data, privateKey);
  }

  async copyToClipboard(text: string): Promise<void> {
    await navigator.clipboard.writeText(text);
  }
}

export { decodeTicket, decodeTicketFromBytes } from './decoder';
export { encodeTicket, encodeTicketToBytes } from './encoder';
export { hasLevel2Signature, verifySignatures, verifyLevel2Signature, verifyLevel1Signature } from './verifier';
export { getSigningAlgorithm, getKeyAlgorithm } from './oids';
export { createUicKeyProvider, parseKeysXml, extractPublicKeyFromDer, base64ToBytes, UIC_PUBLIC_KEY_URL } from './key-provider';
export { SAMPLE_TICKET_HEX, SNCF_TER_TICKET_HEX, SOLEA_TICKET_HEX, CTS_TICKET_HEX, GRAND_EST_U1_FCB3_HEX } from './fixtures';

export type {
  UicBarcodeTicket,
  SecurityInfo,
  DataBlock,
  RailTicketData,
  IssuingDetail,
  ExtensionData,
  IntercodeIssuingData,
  IntercodeDynamicData,
  RetailChannel,
  ProductRetailerData,
  TravelerDetail,
  TravelerInfo,
  CustomerStatus,
  TransportDocumentEntry,
  ControlDetail,
  CardReference,
  TicketLink,
  UicBarcodeTicketInput,
  RailTicketInput,
  IssuingDetailInput,
  IntercodeIssuingDataInput,
  IntercodeDynamicDataInput,
  TravelerDetailInput,
  TransportDocumentInput,
  SignatureVerificationResult,
  SignatureLevelResult,
  VerifyOptions,
  Level1KeyProvider,
} from './types';

export type { SigningAlgorithm, KeyAlgorithm } from './oids';
export type { SignedDataBytes } from './signed-data';
export type { UicPublicKeyEntry } from './key-provider';

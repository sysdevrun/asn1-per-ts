export { decodeTicket, decodeTicketFromBytes } from './decoder';
export { encodeTicket, encodeTicketToBytes } from './encoder';
export { SAMPLE_TICKET_HEX, GRAND_EST_U1_FCB3_HEX } from './fixtures';
export { verifySignatures, verifyLevel1Signature, verifyLevel2Signature } from './verifier';
export { extractSignedData } from './signed-data';
export { getSigningAlgorithm, getKeyAlgorithm } from './oids';
export { importSpkiPublicKey } from './signature-utils';

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
  SingleVerificationResult,
  SignatureVerificationResult,
  VerifyOptions,
  Level1KeyProvider,
} from './types';

export type { ExtractedSignedData } from './signed-data';
export type { SigningAlgorithm, KeyAlgorithm } from './oids';

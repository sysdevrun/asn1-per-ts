import { decodeTicket, SAMPLE_TICKET_HEX } from '../src';

describe('decodeTicket', () => {
  it('decodes the sample fixture', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);

    expect(ticket.format).toBe('U1');
    expect(ticket.headerVersion).toBe(1);
    expect(ticket.level2Signature).toBeDefined();
    expect(ticket.level2Signature!.length).toBe(64);
  });

  it('extracts security info', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    expect(ticket.security.securityProviderNum).toBe(3703);
    expect(ticket.security.keyId).toBe(1);
    expect(ticket.security.level1KeyAlg).toBe('1.2.840.10045.3.1.7');
    expect(ticket.security.level2KeyAlg).toBe('1.2.840.10045.3.1.7');
    expect(ticket.security.level2SigningAlg).toBe('1.2.840.10045.4.3.2');
    expect(ticket.security.level2PublicKey).toBeDefined();
    expect(ticket.security.level1Signature).toBeDefined();
  });

  it('decodes FCB2 rail ticket data', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    expect(ticket.railTickets).toHaveLength(1);

    const rt = ticket.railTickets[0];
    expect(rt.fcbVersion).toBe(2);
    expect(rt.issuingDetail).toBeDefined();
    expect(rt.issuingDetail!.issuingYear).toBe(2020);
    expect(rt.issuingDetail!.issuingDay).toBe(121);
    expect(rt.issuingDetail!.issuingTime).toBe(995);
    expect(rt.issuingDetail!.specimen).toBe(false);
    expect(rt.issuingDetail!.activated).toBe(true);
    expect(rt.issuingDetail!.currency).toBe('EUR');
    expect(rt.issuingDetail!.currencyFract).toBe(2);
  });

  it('decodes Intercode 6 issuing extension', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    const iss = ticket.railTickets[0].issuingDetail!;
    expect(iss.intercodeIssuing).toBeDefined();
    expect(iss.intercodeIssuing!.intercodeVersion).toBe(1);
    expect(iss.intercodeIssuing!.intercodeInstanciation).toBe(1);
    expect(iss.intercodeIssuing!.networkId).toBeDefined();
    expect(iss.intercodeIssuing!.productRetailer).toBeDefined();
    expect(iss.intercodeIssuing!.productRetailer!.retailChannel).toBe('mobileApplication');
  });

  it('decodes transport documents', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    const rt = ticket.railTickets[0];
    expect(rt.transportDocument).toBeDefined();
    expect(rt.transportDocument!.length).toBe(1);
    expect(rt.transportDocument![0].ticketType).toBe('openTicket');
  });

  it('decodes Intercode 6 dynamic data', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    expect(ticket.dynamicData).toBeDefined();
    expect(ticket.dynamicData!.dynamicContentDay).toBe(0);
    expect(ticket.dynamicData!.dynamicContentTime).toBe(59710);
    expect(ticket.dynamicData!.dynamicContentUTCOffset).toBe(-8);
    expect(ticket.dynamicData!.dynamicContentDuration).toBe(600);
  });

  it('includes level2 data block', () => {
    const ticket = decodeTicket(SAMPLE_TICKET_HEX);
    expect(ticket.level2DataBlock).toBeDefined();
    expect(ticket.level2DataBlock!.dataFormat).toBe('_3703.ID1');
  });
});

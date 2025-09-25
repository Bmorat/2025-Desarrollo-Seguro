// src/services/invoiceService.ts
import db from '../db';
import { Invoice } from '../types/invoice';
import axios from 'axios';
import { promises as fs } from 'fs';
import * as path from 'path';

interface InvoiceRow {
  id: string;
  userId: string;
  amount: number;
  dueDate: Date;
  status: string;
}

class InvoiceService {
  static async list(userId: string, status?: string, operator?: string): Promise<Invoice[]> {
    let q = db<InvoiceRow>('invoices').where({ userId });
    // Solo permitir operadores seguros para evitar el uso de SQL dinamico
    const allowedOperators = ['=', '!=', '<', '>', '<=', '>='];
    if (status && operator && allowedOperators.includes(operator)) {
      q = q.andWhere('status', operator as any, status);
    } else if (status) {
      q = q.andWhere({ status });
    }
    const rows = await q.select();
    const invoices = rows.map(row => ({
      id: row.id,
      userId: row.userId,
      amount: row.amount,
      dueDate: row.dueDate,
      status: row.status
    } as Invoice));
    return invoices;
  }

  static async setPaymentCard(
    userId: string,
    invoiceId: string,
    paymentBrand: string,
    ccNumber: string,
    ccv: string,
    expirationDate: string
  ) {
    // Validar paymentBrand para evitar SSRF
    // Solo se permite 'visa' o 'master', nunca valores arbitrarios
    // --- SSRF Prevention ---
    // Validamos que paymentBrand solo pueda ser 'visa' o 'master'.
    // Esto evita que un atacante use un dominio arbitrario y fuerce al backend a hacer requests peligrosos.
    // Si se agregan más marcas, deben ser incluidas explícitamente en allowedBrands.
    const allowedBrands = ['visa', 'master'];
    if (!allowedBrands.includes(paymentBrand)) {
      throw new Error('Invalid payment brand');
    }
    // --- END SSRF Prevention ---
    // Si se necesita agregar más marcas, hacerlo aquí y nunca desde la request directamente
    const paymentResponse = await axios.post(`http://${paymentBrand}/payments`, {
      ccNumber,
      ccv,
      expirationDate
    });
    if (paymentResponse.status !== 200) {
      throw new Error('Payment failed');
    }

    // Update the invoice status in the database
    await db('invoices')
      .where({ id: invoiceId, userId })
      .update({ status: 'paid' });
  }
  static async  getInvoice( invoiceId:string): Promise<Invoice> {
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId }).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    return invoice as Invoice;
  }


  static async getReceipt(
    invoiceId: string,
    pdfName: string
  ) {
    // check if the invoice exists
    const invoice = await db<InvoiceRow>('invoices').where({ id: invoiceId }).first();
    if (!invoice) {
      throw new Error('Invoice not found');
    }
    // --- Path Traversal Prevention ---
    // Solo permitimos nombres de archivo válidos: sin ../ ni /
    // Así evitamos que un atacante acceda a archivos fuera de /invoices
    if (!/^[a-zA-Z0-9_.-]+\.pdf$/.test(pdfName)) {
      throw new Error('Invalid PDF name');
    }
    try {
      const filePath = `/invoices/${pdfName}`;
      const content = await fs.readFile(filePath, 'utf-8');
      return content;
    } catch (error) {
      // send the error to the standard output
      console.error('Error reading receipt file:', error);
      throw new Error('Receipt not found');
    }
    // --- END Path Traversal Prevention ---

  };

};

export default InvoiceService;

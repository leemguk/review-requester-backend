// src/routes/upload.ts - NEW FILE
import { Router, Request, Response } from 'express';
import multer from 'multer';
import * as XLSX from 'xlsx';
import { authenticateToken } from '../middleware/auth';
import { logger } from '../utils/logger';

const router = Router();

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      'text/csv',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'text/tab-separated-values'
    ];

    if (allowedTypes.includes(file.mimetype) || 
        file.originalname.toLowerCase().endsWith('.csv') ||
        file.originalname.toLowerCase().endsWith('.xlsx') ||
        file.originalname.toLowerCase().endsWith('.xls') ||
        file.originalname.toLowerCase().endsWith('.tsv')) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only CSV, Excel, and TSV files are allowed.'));
    }
  }
});

interface Customer {
  name: string;
  email: string;
  originalRow: number;
  originalSheet?: string;
}

interface OrderCustomer {
  firstName: string;
  lastName: string;
  email: string;
  orderNumber: string;
  orderDate: string;
  despatchDate: string;
  originalRow: number;
  originalSheet?: string;
  displayName?: string;
  skipReason?: string;
}

interface ProcessedData {
  customers: Customer[];
  skipped: OrderCustomer[];
  sheets: string[];
  headers: string[][];
  validation: {
    valid: number;
    skipped: number;
    skipReasons: Record<string, number>;
  };
  summary: {
    total: number;
    toSend: number;
    skipped: number;
    skipReasons: Record<string, number>;
  };
}
const isWithin36BusinessHours = (orderDateStr: string, despatchDateStr: string): boolean => {
  if (!orderDateStr || !despatchDateStr || orderDateStr.trim() === '' || despatchDateStr.trim() === '') return false;

  try {
    // Parse both dates
    const parseDate = (dateStr: string): Date => {
      if (dateStr.includes(' ')) {
        // Format with time
        const [datePart, timePart] = dateStr.split(' ');

        if (datePart.includes('/')) {
          // DD/MM/YYYY HH:MM:SS format
          const [day, month, year] = datePart.split('/');
          const [hours, minutes, seconds] = (timePart || '00:00:00').split(':');

          return new Date(
            parseInt(year), 
            parseInt(month) - 1, 
            parseInt(day),
            parseInt(hours || '0'),
            parseInt(minutes || '0'),
            parseInt(seconds || '0')
          );
        } else {
          // YYYY-MM-DD HH:MM:SS format
          return new Date(dateStr);
        }
      } else {
        // Just date without time
        if (dateStr.includes('/')) {
          // DD/MM/YYYY format
          const [day, month, year] = dateStr.split('/');
          return new Date(parseInt(year), parseInt(month) - 1, parseInt(day), 12, 0, 0);
        } else {
          // YYYY-MM-DD format
          return new Date(dateStr + 'T12:00:00');
        }
      }
    };

    const orderDate = parseDate(orderDateStr);
    const despatchDate = parseDate(despatchDateStr);

    // Check if dates are valid
    if (isNaN(orderDate.getTime()) || isNaN(despatchDate.getTime())) {
      console.error('Invalid dates:', { orderDateStr, despatchDateStr });
      return false;
    }

    // Calculate business hours between ORDER and DESPATCH
    let businessHours = 0;
    let currentDate = new Date(orderDate);

    while (currentDate < despatchDate) {
      const dayOfWeek = currentDate.getDay(); // 0 = Sunday, 6 = Saturday

      // Skip weekends (Saturday = 6, Sunday = 0)
      if (dayOfWeek !== 0 && dayOfWeek !== 6) {
        const endOfDay = new Date(currentDate);
        endOfDay.setHours(23, 59, 59, 999);

        const endTime = endOfDay < despatchDate ? endOfDay : despatchDate;
        const hoursThisDay = (endTime.getTime() - currentDate.getTime()) / (1000 * 60 * 60);

        businessHours += hoursThisDay;
      }

      // Move to next day
      currentDate.setDate(currentDate.getDate() + 1);
      currentDate.setHours(0, 0, 0, 0);
    }

    return businessHours <= 36;

  } catch (error) {
    console.error('Error parsing dates:', { orderDateStr, despatchDateStr }, error);
    return false;
  }
};

const formatCustomerName = (firstName: string, lastName: string): string => {
  const titleWords = ['MR', 'MRS', 'MISS', 'MS', 'DR', 'SIR', 'LADY'];
  const firstNameUpper = firstName.toUpperCase();

  // Check if firstName is a title or single letter - these need special handling
  const isTitle = titleWords.includes(firstNameUpper);
  const isSingleLetter = firstName.length === 1;

  if (isTitle || isSingleLetter) {
    // Smart handling: Use both first name (title/initial) and last name
    // Examples: "Hello MR Smith", "Hello K Pudney"
    return `${firstName} ${lastName}`.trim();
  } else {
    // Default: Use just the first name for personal feel
    // Examples: "Hello John", "Hello Sarah", "Hello Michael"
    return firstName;
  }
};

const detectOrderColumns = (headers: string[]): {
  firstName: number;
  lastName: number;
  email: number;
  orderNumber: number;
  orderDate: number;
  despatchDate: number;
} => {
  const headerRow = headers.map(h => (h || '').toString().toLowerCase());

  const firstNameIndex = headerRow.findIndex(h => 
    h.includes('first') || h.includes('fname') || h.includes('given') || 
    h.includes('customer') && h.includes('first')
  );

  const lastNameIndex = headerRow.findIndex(h => 
    h.includes('last') || h.includes('surname') || h.includes('family') ||
    h.includes('customer') && h.includes('last')
  );

  const emailIndex = headerRow.findIndex(h => 
    h.includes('email') || h.includes('mail') || h.includes('@')
  );

  const orderNumberIndex = headerRow.findIndex(h => 
    (h.includes('order') && (h.includes('number') || h.includes('id') || h.includes('#'))) ||
    h.includes('order_number') || h.includes('orderid') || h.includes('order_id')
  );

  const orderDateIndex = headerRow.findIndex(h => 
    (h.includes('order') && h.includes('date')) || 
    h.includes('created') || h.includes('placed') ||
    h.includes('order_date') || h.includes('orderdate')
  );

  const despatchDateIndex = headerRow.findIndex(h => 
    h.includes('despatch') || h.includes('dispatch') || 
    h.includes('shipped') || h.includes('delivery')
  );

  return {
    firstName: firstNameIndex >= 0 ? firstNameIndex : 0,
    lastName: lastNameIndex >= 0 ? lastNameIndex : 1,
    email: emailIndex >= 0 ? emailIndex : 2,
    orderNumber: orderNumberIndex >= 0 ? orderNumberIndex : 3,
    orderDate: orderDateIndex >= 0 ? orderDateIndex : 4,
    despatchDate: despatchDateIndex >= 0 ? despatchDateIndex : 5
  };
};

const processOrderData = (
  data: string[][], 
  columnMappings: {
    firstName: number;
    lastName: number;
    email: number;
    orderNumber: number;
    orderDate: number;
    despatchDate: number;
  },
  sheetName?: string
): { toSend: OrderCustomer[]; skipped: OrderCustomer[] } => {

  const toSend: OrderCustomer[] = [];
  const skipped: OrderCustomer[] = [];
  const processedOrders = new Set<string>();
  const emailOrderCombos = new Map<string, Set<string>>();

  // Skip header row (index 0)
  for (let i = 1; i < data.length; i++) {
    const row = data[i];

    // Skip rows that don't have enough columns
    if (row.length <= Math.max(...Object.values(columnMappings))) continue;

    const firstName = (row[columnMappings.firstName] || '').toString().trim();
    const lastName = (row[columnMappings.lastName] || '').toString().trim();
    const email = (row[columnMappings.email] || '').toString().trim().toLowerCase();
    const orderNumber = (row[columnMappings.orderNumber] || '').toString().trim();
    const orderDate = (row[columnMappings.orderDate] || '').toString().trim();
    const despatchDate = (row[columnMappings.despatchDate] || '').toString().trim();

    const customer: OrderCustomer = {
      firstName,
      lastName,
      email,
      orderNumber,
      orderDate,
      despatchDate,
      originalRow: i + 1,
      originalSheet: sheetName
    };

    // Business Rule 1: Skip if no order number
    if (!orderNumber) {
      customer.skipReason = 'No order number';
      skipped.push(customer);
      continue;
    }

    // Business Rule 2: Skip if no email or invalid email
    if (!email || !validateEmail(email)) {
      customer.skipReason = 'Invalid or missing email';
      skipped.push(customer);
      continue;
    }

    // Business Rule 3: Skip if no name data
    if (!firstName && !lastName) {
      customer.skipReason = 'No customer name';
      skipped.push(customer);
      continue;
    }

    // Business Rule 4: Skip if despatch date is older than 36 business hours
      if (!isWithin36BusinessHours(orderDate, despatchDate)) {
      customer.skipReason = 'Despatch date older than 36 business hours';
      skipped.push(customer);
      continue;
    }

    // Business Rule 5: Only send once per order number
    if (processedOrders.has(orderNumber)) {
      customer.skipReason = 'Duplicate order number';
      skipped.push(customer);
      continue;
    }

    // Business Rule 6: For same email, only send if order number AND date are different
    if (!emailOrderCombos.has(email)) {
      emailOrderCombos.set(email, new Set());
    }

    const emailOrders = emailOrderCombos.get(email)!;
    const orderKey = `${orderNumber}_${orderDate}`;

    if (emailOrders.has(orderKey)) {
      customer.skipReason = 'Same email with same order number and date';
      skipped.push(customer);
      continue;
    }

    // Business Rule 7: Smart name formatting
    customer.displayName = formatCustomerName(firstName, lastName);

    // If we get here, the customer should be included
    processedOrders.add(orderNumber);
    emailOrders.add(orderKey);
    toSend.push(customer);
  }

  return { toSend, skipped };
};

const validateEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const parseCSV = (text: string, delimiter: string = ','): string[][] => {
  const lines = text.split('\n');
  const result: string[][] = [];

  for (let line of lines) {
    if (line.trim() === '') continue;

    // Handle quoted fields
    const row: string[] = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
      const char = line[i];

      if (char === '"' && (i === 0 || line[i-1] === delimiter)) {
        inQuotes = true;
      } else if (char === '"' && inQuotes && (i === line.length - 1 || line[i+1] === delimiter)) {
        inQuotes = false;
      } else if (char === delimiter && !inQuotes) {
        row.push(current.trim());
        current = '';
      } else {
        current += char;
      }
    }
    row.push(current.trim());

    result.push(row);
  }

  return result;
};

// POST /api/upload/process - Process uploaded file
router.post('/process', 
  authenticateToken,
  upload.single('file'),
  async (req: Request, res: Response) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          success: false,
          error: 'No file uploaded'
        });
      }

      const file = req.file;
      const fileName = file.originalname.toLowerCase();
      let allSheetData: Record<string, string[][]> = {};
      let sheets: string[] = [];

      logger.info(`Processing file: ${file.originalname}, size: ${file.size}, type: ${file.mimetype}`);

      // Process based on file type
      if (fileName.endsWith('.xlsx') || fileName.endsWith('.xls')) {
        // Excel file processing
        const workbook = XLSX.read(file.buffer, {
          type: 'buffer',
          cellText: false,
          cellDates: true,
          raw: false
        });

        sheets = workbook.SheetNames;

        for (const sheetName of sheets) {
          const worksheet = workbook.Sheets[sheetName];
          const jsonData = XLSX.utils.sheet_to_json(worksheet, {
            header: 1,
            raw: false,
            dateNF: 'yyyy-mm-dd',
            defval: ''
          }) as string[][];

          // Filter out completely empty rows
          const filteredData = jsonData.filter(row => 
            row.some(cell => cell && cell.toString().trim() !== '')
          );

          allSheetData[sheetName] = filteredData;
        }

      } else if (fileName.endsWith('.csv')) {
        // CSV file processing
        const text = file.buffer.toString('utf-8');
        const csvData = parseCSV(text);
        allSheetData['Sheet1'] = csvData;
        sheets = ['Sheet1'];

      } else if (fileName.endsWith('.tsv')) {
        // TSV file processing
        const text = file.buffer.toString('utf-8');
        const tsvData = parseCSV(text, '\t');
        allSheetData['Sheet1'] = tsvData;
        sheets = ['Sheet1'];

      } else {
        return res.status(400).json({
          success: false,
          error: 'Unsupported file format'
        });
      }

      // Process first sheet by default
      const firstSheet = sheets[0];
      const firstSheetData = allSheetData[firstSheet];

      if (!firstSheetData || firstSheetData.length < 2) {
        return res.status(400).json({
          success: false,
          error: 'File must contain at least a header row and one data row'
        });
      }

      // Apply business logic processing
      const columnMappings = detectOrderColumns(firstSheetData[0]);
      const { toSend, skipped } = processOrderData(firstSheetData, columnMappings, firstSheet);

      // Generate summary statistics
      const skipReasons: Record<string, number> = {};
      skipped.forEach(customer => {
        const reason = customer.skipReason || 'Unknown';
        skipReasons[reason] = (skipReasons[reason] || 0) + 1;
      });

      // Convert to existing Customer format for compatibility
      const validCustomers: Customer[] = toSend.map(customer => ({
        name: customer.displayName || customer.firstName,
        email: customer.email,
        originalRow: customer.originalRow,
        originalSheet: customer.originalSheet
      }));

      const response: ProcessedData = {
        customers: validCustomers,
        skipped: skipped,
        sheets,
        headers: [firstSheetData[0]],
        validation: {
          valid: toSend.length,
          skipped: skipped.length,
          skipReasons: skipReasons
        },
        summary: {
          total: firstSheetData.length - 1,
          toSend: toSend.length,
          skipped: skipped.length,
          skipReasons: skipReasons
        }
      };

      logger.info(`Order file processed: ${toSend.length} customers to send, ${skipped.length} skipped`);

      res.json({
        success: true,
        data: response
      });

    } catch (error) {
      logger.error('File processing error:', error);
      res.status(500).json({
        success: false,
        error: 'Failed to process file',
        details: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
);

export default router;
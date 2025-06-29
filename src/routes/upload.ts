// COMPLETE src/routes/upload.ts file - Replace your entire file with this

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
  originalRow?: number;
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

// FIXED: Same-day despatch validation with proper typing
// FIXED: Same-day despatch validation with proper UK date parsing
const isSameDayDespatch = (orderDateStr: string | Date, despatchDateStr: string | Date): boolean => {
  if (!orderDateStr || !despatchDateStr) {
    return false;
  }

  try {
    let orderDate: Date;
    let despatchDate: Date;

    // Helper function to parse UK date format (dd/mm/yyyy hh:mm:ss)
    const parseUKDate = (dateInput: string | Date): Date => {
      if (dateInput instanceof Date) {
        return dateInput;
      }

      const dateStr = dateInput.toString().trim();

      // Handle UK format: dd/mm/yyyy hh:mm:ss
      if (dateStr.includes('/')) {
        const [datePart, timePart] = dateStr.split(' ');
        const [day, month, year] = datePart.split('/');

        // Convert to US format for JavaScript Date constructor
        const usFormat = `${month}/${day}/${year}${timePart ? ' ' + timePart : ''}`;
        return new Date(usFormat);
      }

      // Fallback to direct parsing
      return new Date(dateInput);
    };

    orderDate = parseUKDate(orderDateStr);
    despatchDate = parseUKDate(despatchDateStr);

    if (isNaN(orderDate.getTime()) || isNaN(despatchDate.getTime())) {
      console.error('Invalid dates after parsing:', { 
        orderDateStr, 
        despatchDateStr, 
        parsedOrder: orderDate, 
        parsedDespatch: despatchDate 
      });
      return false;
    }

    // Extract just the date components (ignore time for day comparison)
    const orderDay = new Date(orderDate.getFullYear(), orderDate.getMonth(), orderDate.getDate());
    const despatchDay = new Date(despatchDate.getFullYear(), despatchDate.getMonth(), despatchDate.getDate());

    // Get the order hour for 3pm cutoff logic
    const orderHour = orderDate.getHours();
    const orderDayOfWeek = orderDay.getDay(); // 0=Sunday, 1=Monday, ..., 6=Saturday

    // Debug logging
    console.log(`Order: ${orderDateStr} → ${orderDate.toISOString()} (${['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][orderDayOfWeek]} ${orderHour}:00)`);
    console.log(`Despatch: ${despatchDateStr} → ${despatchDate.toISOString()}`);

    // WEEKEND ORDERS (Saturday=6 or Sunday=0)
    if (orderDayOfWeek === 0 || orderDayOfWeek === 6) {
      console.log('🔄 Weekend order detected - must despatch by Monday 3pm');

      // Find Monday 3pm from the order date
      const monday = new Date(orderDay);

      // Calculate days to add to get to Monday
      if (orderDayOfWeek === 0) { // Sunday
        monday.setDate(monday.getDate() + 1); // Monday is next day
      } else { // Saturday
        monday.setDate(monday.getDate() + 2); // Monday is in 2 days
      }

      monday.setHours(15, 0, 0, 0); // Set to 3:00 PM

      const isValid = despatchDate.getTime() <= monday.getTime();
      console.log(`Monday 3pm deadline: ${monday.toISOString()}`);
      console.log(`Despatch: ${despatchDate.toISOString()}`);
      console.log(`Valid? ${isValid ? '✅' : '❌'}`);

      return isValid;
    }

    // WEEKDAY ORDERS (Monday-Friday)
    console.log('🔄 Weekday order');

    // Rule: Orders before 3pm (15:00) must despatch same day
    if (orderHour < 15) {
      console.log('⏰ Before 3pm - must despatch same day');
      const isValid = orderDay.getTime() === despatchDay.getTime();
      console.log(`Same day despatch? ${isValid ? '✅' : '❌'}`);
      return isValid;
    }

    // Rule: Orders at/after 3pm can despatch same day OR next working day
    else {
      console.log('⏰ After 3pm - can despatch same day or next working day');

      // Check if it's same day despatch
      const sameDayDespatch = orderDay.getTime() === despatchDay.getTime();

      if (sameDayDespatch) {
        console.log('✅ Same day despatch');
        return true;
      }

      // Calculate next working day from order date
      const nextWorkingDay = new Date(orderDay);
      nextWorkingDay.setDate(nextWorkingDay.getDate() + 1);

      // Skip weekends for next day despatch
      while (nextWorkingDay.getDay() === 0 || nextWorkingDay.getDay() === 6) {
        nextWorkingDay.setDate(nextWorkingDay.getDate() + 1);
      }

      const nextDayDespatch = nextWorkingDay.getTime() === despatchDay.getTime();
      console.log(`Next working day despatch? ${nextDayDespatch ? '✅' : '❌'}`);

      return nextDayDespatch;
    }

  } catch (error) {
    console.error('Error in same-day despatch validation:', error);
    return false;
  }
};

// NEW: Proper name capitalization functions
const capitalizeWord = (word: string): string => {
  if (!word || word.length === 0) return word;

  const specialPrefixes = ['mc', 'mac', 'o\''];
  const lowerWord = word.toLowerCase();

  for (const prefix of specialPrefixes) {
    if (lowerWord.startsWith(prefix)) {
      if (prefix === 'o\'') {
        return 'O\'' + word.slice(2, 3).toUpperCase() + word.slice(3).toLowerCase();
      } else {
        return prefix.charAt(0).toUpperCase() + prefix.slice(1) + 
               word.slice(prefix.length, prefix.length + 1).toUpperCase() + 
               word.slice(prefix.length + 1).toLowerCase();
      }
    }
  }

  if (word.includes('-')) {
    return word.split('-')
      .map(part => capitalizeWord(part))
      .join('-');
  }

  return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
};

const capitalizeName = (name: string): string => {
  if (!name || name.trim() === '') return name;

  return name.trim()
    .split(/\s+/)
    .map(word => capitalizeWord(word))
    .join(' ');
};

// UPDATED: Format customer names with proper capitalization
const formatCustomerName = (firstName: string, lastName: string): string => {
  const capitalizedFirstName = capitalizeName(firstName);
  const capitalizedLastName = capitalizeName(lastName);

  const titleWords = ['Mr', 'Mrs', 'Miss', 'Ms', 'Dr', 'Sir', 'Lady'];

  const isTitle = titleWords.some(title => 
    capitalizedFirstName.toLowerCase() === title.toLowerCase()
  );
  const isSingleLetter = capitalizedFirstName.length === 1;

  if (isTitle || isSingleLetter) {
    return `${capitalizedFirstName} ${capitalizedLastName}`.trim();
  } else {
    return capitalizedFirstName;
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

  for (let i = 1; i < data.length; i++) {
    const row = data[i];

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

    // Business Rule 4: Skip if not same-day despatch
    if (!isSameDayDespatch(orderDate, despatchDate)) {
      customer.skipReason = 'Not same-day despatch (orders before 3pm must despatch same day, weekday orders after 3pm can despatch next working day, weekend orders must despatch by Monday 3pm)';
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

    // Business Rule 7: UPDATED - Smart name formatting with capitalization
    customer.displayName = formatCustomerName(firstName, lastName);

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

      if (fileName.endsWith('.xlsx') || fileName.endsWith('.xls')) {
        const workbook = XLSX.read(file.buffer, {
          type: 'buffer',
          cellText: false,
          cellDates: true,
          raw: true  // Keep raw values to preserve time data
        });

        sheets = workbook.SheetNames;

        for (const sheetName of sheets) {
          const worksheet = workbook.Sheets[sheetName];
          const jsonData = XLSX.utils.sheet_to_json(worksheet, {
            header: 1,
            raw: true,  // Keep raw values
            dateNF: 'dd/mm/yyyy hh:mm:ss',  // Preserve time format
            defval: ''
          }) as string[][];

          // Convert Excel date numbers to proper date strings
          const convertedData = jsonData.map((row, rowIndex) => {
            return row.map((cell, colIndex) => {
              if (typeof cell === 'number' && cell > 25000 && cell < 100000) {
                // This looks like an Excel date serial number
                const excelDate = XLSX.SSF.format('dd/mm/yyyy hh:mm:ss', cell);
                console.log(`Converting Excel date: ${cell} → ${excelDate}`);
                return excelDate;
              }
              return cell;
            });
          });

          const filteredData = convertedData.filter(row => 
            row.some(cell => cell && cell.toString().trim() !== '')
          );

          allSheetData[sheetName] = filteredData;
        }

      } else if (fileName.endsWith('.csv')) {
        const text = file.buffer.toString('utf-8');
        const csvData = parseCSV(text);
        allSheetData['Sheet1'] = csvData;
        sheets = ['Sheet1'];

      } else if (fileName.endsWith('.tsv')) {
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

      const firstSheet = sheets[0];
      const firstSheetData = allSheetData[firstSheet];

      if (!firstSheetData || firstSheetData.length < 2) {
        return res.status(400).json({
          success: false,
          error: 'File must contain at least a header row and one data row'
        });
      }

      const columnMappings = detectOrderColumns(firstSheetData[0]);
      const { toSend, skipped } = processOrderData(firstSheetData, columnMappings, firstSheet);

      const skipReasons: Record<string, number> = {};
      skipped.forEach(customer => {
        const reason = customer.skipReason || 'Unknown';
        skipReasons[reason] = (skipReasons[reason] || 0) + 1;
      });

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

      logger.info(`File processed with name capitalization: ${toSend.length} customers to send, ${skipped.length} skipped`);

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
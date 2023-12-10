import nodemailer from 'nodemailer'
import handlebars from 'handlebars';
import fs from 'fs';
import path, {dirname} from 'path'
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

class EmailModule {
  constructor(config) {
    this.transporter = nodemailer.createTransport(config);
  }

  async sendEmail(templateName, data, options) {
    const emailContent = this.parseTemplate(templateName, data);

    const mailOptions = {
      from: options.from,
      to: options.to,
      subject: options.subject,
      text: emailContent.text,
      html: emailContent.html,
    };

    try {
      const info = await this.transporter.sendMail(mailOptions);
      return info;
    } catch (error) {
      console.error('Error sending email:', error.message);
      throw error;
    }
  }

  parseTemplate(templateName, data) {
    const templatePath = path.join(__dirname, 'templates', templateName);

    const textTemplate = fs.readFileSync(`${templatePath}/text.hbs`, 'utf-8');
    const htmlTemplate = fs.readFileSync(`${templatePath}/html.hbs`, 'utf-8');

    const compiledTextTemplate = handlebars.compile(textTemplate);
    const compiledHtmlTemplate = handlebars.compile(htmlTemplate);

    const textContent = compiledTextTemplate(data);
    const htmlContent = compiledHtmlTemplate(data);

    return { text: textContent, html: htmlContent };
  }
}

export default EmailModule;

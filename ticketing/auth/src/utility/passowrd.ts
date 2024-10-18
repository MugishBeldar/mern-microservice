import bcrypt from 'bcrypt';

export class Password {
  // Static method to hash the password
  static async hashPassword(password: string): Promise<string> {
    const saltRounds = 10; // Define the cost factor for the hash
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    return hashedPassword;
  }

  // Static method to compare the password with a hashed password
  static async comparePassword(storedPassword: string, suppliedPassword: string): Promise<boolean> {
    const isMatch = await bcrypt.compare(suppliedPassword, storedPassword);
    return isMatch;
  }
}
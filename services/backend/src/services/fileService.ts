// src/services/fileService.ts
import fs from 'fs';
import path from 'path';
import { promisify } from 'util';
import db from '../db';

const unlink = promisify(fs.unlink);

class FileService {
  static async saveProfilePicture(
    userId: string,
    file: any //Express.Multer.File
  ): Promise<string> {
    const user = await db('users')
      .select('picture_path')
      .where({ id: userId })
      .first();
    if (!user) throw new Error('User not found');

    if (user.picture_path) {
      // --- Path Traversal Prevention ---
      // Solo permitimos rutas de archivo válidas: sin ../ ni /
      // Así evitamos que un atacante acceda a archivos fuera de la carpeta permitida
      if (!/^[a-zA-Z0-9_.\/-]+$/.test(user.picture_path)) {
        throw new Error('Invalid picture path');
      }
      try { await unlink(path.resolve(user.picture_path)); } catch { /*ignore*/ }
      // --- END Path Traversal Prevention ---
    }

    // Validar file.path antes de guardar
    if (!/^[a-zA-Z0-9_.\/-]+$/.test(file.path)) {
      throw new Error('Invalid file path');
    }
    await db('users')
      .update({ picture_path: file.path })
      .where({ id: userId });

    return `${process.env.API_BASE_URL}/uploads/${path.basename(file.path)}`;
  }

  static async getProfilePicture(userId: string) {
    const user = await db('users')
      .select('picture_path')
      .where({ id: userId })
      .first();
    if (!user || !user.picture_path) throw new Error('No profile picture');

    const filePath = user.picture_path;
    const stream   = fs.createReadStream(filePath);
    const ext      = path.extname(filePath).toLowerCase();
    const contentType =
      ext === '.png'  ? 'image/png'  :
      ext === '.jpg'  ? 'image/jpeg' :
      ext === '.jpeg'? 'image/jpeg' : 
      'application/octet-stream';

    return { stream, contentType };
  }

  static async deleteProfilePicture(userId: string) {
    const user = await db('users')
      .select('picture_path')
      .where({ id: userId })
      .first();
    if (!user || !user.picture_path) throw new Error('No profile picture');

    // --- Path Traversal Prevention ---
    // Solo permitimos rutas de archivo válidas: sin ../ ni /
    if (!/^[a-zA-Z0-9_.\/-]+$/.test(user.picture_path)) {
      throw new Error('Invalid picture path');
    }
    try { await unlink(path.resolve(user.picture_path)); } catch { /*ignore*/ }
    // --- END Path Traversal Prevention ---

    await db('users')
      .update({ picture_path: null })
      .where({ id: userId });
  }
}

export default FileService;

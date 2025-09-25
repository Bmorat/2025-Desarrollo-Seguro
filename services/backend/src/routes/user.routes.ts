import { Router } from 'express';
import routes from '../controllers/authController';
import authenticateJWT from '../middleware/auth.middleware';

const router = Router();

// POST /auth to create a new user
// Solo usuarios autenticados pueden crear usuarios (puedes ajustar la lógica según tu caso de uso)
router.post('/', authenticateJWT, routes.createUser);

// PUT /auth/:id to update an existing user
// Solo usuarios autenticados pueden modificar usuarios
router.put('/:id', authenticateJWT, routes.updateUser);




//router.get('/:id/picture', routes.getUser);
//router.post('/:id/picture', routes.getUser);
//router.delete('/:id/picture', routes.getUser);


export default router;

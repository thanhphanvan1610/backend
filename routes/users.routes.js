import {Router} from 'express';
import * as User from '../controllers/users.controllers.js';

const router = Router();

/**
 * @swagger
 * components:
 *   schemas:
 *     User:
 *       type: object
 *       required:
 *         - username
 *         - email
 *       properties:
 *         id:
 *           type: string
 *           description: The auto-generated id of the user
 *         username:
 *           type: string
 *           description: The name of the user
 *         email:
 *           type: string
 *           description: The email of the user
 *       example:
 *         id: d290f1ee-6c54-4b01-90e6-d701748f0851
 *         username: johndoe
 *         email: johndoe@example.com
 */

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Retrieve a list of users
 *     parameters:
 *          id: 
 *              type: string
 *     responses:
 *       200:
 *         description: A list of users was retrieved successfully.
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/User'
 *       404:
 *         description: The user list was not found.
 * 
 * 
 */



router.get('/', User.getUsers);
router.put('/:id', User.updateUser)
router.get('/:id', User.getUserById)
router.delete('/:id', User.deleteUser)
router.delete('/', User.deleteAllUser)
router.post('/ban', User.banUser)
router.post('/unban', User.unBanUser)



const userRoutes = router;
export default userRoutes;

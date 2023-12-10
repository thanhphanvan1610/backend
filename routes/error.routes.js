import {Router} from 'express';

const router = Router();

const handleUnauthenticated = (req, res) => {
    return res.status(401).json({
        status: 'failed',
        message: 'Unauthenticated <Route>',
        code: 401
    });
}

router.get('*', (req, res) => {
    return res.status(404).json({
        status: 'failed',
        message: 'Route not found',
        code: 404
    });
})

router.post('*', handleUnauthenticated);
router.put('*', handleUnauthenticated);
router.delete('*', handleUnauthenticated);

const errorRoutes = router;
export default errorRoutes;

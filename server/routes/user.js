import { express } from 'express';
import { AddToFavorites,
    GetUserFavorites,
    RemoveFromFavorites,
    SignUp,
    SignIn,
    BookProperty,
    GetBookProperty,
 } from '../controllers/user';
import { verifyToken } from './../middlewares/verifyToken.js';

const router = express.Router();

router.post("/signup", SignUp);
router.post("/signin", SignIn);
router.post("/addToFavorites",[verifyToken], AddToFavorites); 
router.get("/getFavorites",[verifyToken], GetUserFavorites); 
router.post("/removeFavorites",[verifyToken], RemoveFromFavorites); 
router.post("/booking",[verifyToken], BookProperty); 
router.post("/getBooking",[verifyToken], GetBookProperty); 

export default router;

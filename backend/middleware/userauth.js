import jwt from "jsonwebtoken";

const userAuth = async(req, res, next)=>{
    const {token} = req.cookies;

    if(!token){
        return res.json({success:false, messgae:'not authorized bro get lost and come after authorization'})
        
    }
    try {


        const toeknDecode = jwt.verify(token, process.env.JWT_SECRET);

        if (toeknDecode.id) {
            req.body.userId = toeknDecode.id
            
        } else {
            return res.json({success:false, messgae:'login again not authorized'});
            next();

            
        }
        
    } catch (error) {
        return res.json({success:false, messgae:error.messgae})

        
    }
}

export default userAuth;

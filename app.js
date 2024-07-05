const express = require('express');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const path = require('path');
const mongoose = require('mongoose');
const bcrypt = require("bcrypt")


const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'your_secret_key';
const saltRounds = 5;

mongoose.set('strictQuery', false);

const uri =  "mongodb://adminUser:fullstack@localhost:27017";
mongoose.connect(uri,{'dbName':'SocialDB'});

const User = mongoose.model('User', { username: String, email: String, password: String });
const Post = mongoose.model('Post', { userId: mongoose.Schema.Types.ObjectId, text: String });


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: SECRET_KEY, resave: false, saveUninitialized: true, cookie: { secure: false } }));



function authenticateJWT(req,res,next){
    const token = req.session.token;
    if(!token) return res.status(401).json({message:"Unauthorized"});
    try{
        const decoded = jwt.verify(token,SECRET_KEY);
        req.user = decoded;
        next();
    }catch(error){
        return res.status(401).json({message:"Invalid token"});
    }
}


function requireAuth(req,res,next){
    const token = req.session.token;
    if(!token) return res.redirect("/login");
    try{
        const decoded = jwt.verify(token,SECRET_KEY);
        req.user = decoded;
        next();
    }catch(error){
        return res.redirect("/login");
    }
}



app.get("/",(req,res)=> res.sendFile(path.join(__dirname,"public","index.html")));
app.get("/register",(req,res)=>res.sendFile(path.join(__dirname,"public","register.html")));
app.get("/login",(req,res)=>res.sendFile(path.join(__dirname,"public","login.html")));
app.get("/post",requireAuth,(req,res)=>res.sendFile(path.join(__dirname,"public","post.html")));
app.get('/index', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.post("/register",async (req,res) =>{
    const {username,email,password} = req.body;
    try{
        const existingUser = await User.findOne({$or:[{username},{email}]});
        if(existingUser){
            return res.status(400).json({message:"User already exists"});
        }
        let hashedPassword = await bcrypt.hash(password,saltRounds);
        const newUser = new User({username,email,password:hashedPassword});
        await newUser.save();
        const token = jwt.sign({userId:newUser._id,username:newUser.username},SECRET_KEY,{expiresIn:"1h"});
        req.session.token = token;
        res.redirect(`/index?username=${newUser.username}`);
    } catch (error){
        console.error(error);
        res.status(500).json({message:"Internal Server Error"});
    }
})

app.post("/login",async (req,res)=>{
    const {username, email,password} = req.body;
    try {
        const user = await User.findOne({$or:[{username},{email}]});
        if(!user) {
            return res.status(401).json({message:"Invalid credentials"})
        }
        console.log("password",password,user.password);
        const result = await bcrypt.compare(password,user.password);
        if (result) {
            const token = jwt.sign({userId:user._id,username:user.username},SECRET_KEY,{expiresIn:"1h"});
            req.session.token = token;
            res.redirect(`/index?username=${user.username}`);
        } else {
             return res.status(401).json({message:"Invalid credentials"})
        }

    } catch (error) {
        console.error('Error:', error);
    }
})
//get all posts
app.get("/posts",async (req,res)=>{
   const result =  await Post.find();
   res.send(result);
})



//  post creation  .
app.post("/posts",authenticateJWT,async (req,res)=>{
    const {text} = req.body;
    if(!text || typeof text!== 'string') {
        return res.status(400).json({message:"please provide valid post content"});
    }
    const newPost = new Post({userId: req.user.userId,text}) ;
    await newPost.save();

    res.status(201).json(newPost);
})

// post updation .

app.put("/posts/:postId",authenticateJWT,async (req,res)=>{
    const postId = req.params.postId;
    const post = await Post.findOne( {$and:[{_id:postId},{userId:req.user.userId}] });
    if(!post) return res.status(404).json({message:"Post not found"});
    await Post.updateOne({_id:postId},{text:req.body.text})
    res.json({message:"post updated successfully"});
})

// post deletion .
app.delete("/posts/:postId",authenticateJWT,async (req,res)=>{
    const postId = req.params.postId;
    const post = await Post.findOne( {$and:[{_id:postId},{userId:req.user.userId}] });
    if(!post){
        return res.status(404).json({message:"Post not found"});
    }
    await Post.deleteOne({_id:postId})
    res.json({message:"Post deleted successfully"});
})

// user logout .

app.get("/logout",(req,res)=>{
    req.session.destroy((err)=>{
        if(err) console.err(err);
        res.redirect("/login");
    })
})
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));

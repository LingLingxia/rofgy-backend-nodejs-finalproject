const express = require('express');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const path = require('path');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'your_secret_key';

mongoose.set('strictQuery', false);

const uri =  "mongodb://adminUser:fullstack@localhost:27017";
mongoose.connect(uri,{'dbName':'SocialDB'});

const User = mongoose.model('User', { username: String, email: String, password: String });
const Post = mongoose.model('Post', { userId: mongoose.Schema.Types.ObjectId, text: String });

const posts = [];//I don't know what's this 
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: SECRET_KEY, resave: false, saveUninitialized: true, cookie: { secure: false } }));


// Insert your authenticateJWT Function code here.
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

// Insert your requireAuth Function code here.
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


// Insert your routing HTML code here.
app.get("/",(req,res)=> res.sendFile(path.join(__dirname,"public","index.html")));
app.get("/register",(req,res)=>res.sendFile(path.join(__dirname,"public","register.html")));
app.get("/login",(req,res)=>res.sendFile(path.join(__dirname,"public","login.html")));
app.get("/post",requireAuth,(req,res)=>res.sendFile(path.join(__dirname,"public","post.html")));
app.get('/index', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
// Insert your user registration code here.
app.post("/register",async (req,res) =>{
    const {username,email,password} = req.body;
    try{
        const existingUser = await User.findOne({$or:[{username},{email}]});
        if(existingUser){
            return res.status(400).json({message:"User already exists"});
        }
        const newUser = new User({username,email,password});
        await newUser.save();
        const token = jwt.sign({userId:newUser._id,username:newUser.username},SECRET_KEY,{expiresIn:"1h"});
        req.session.token = token;
        res.redirect(`/index?username=${newUser.username}`);
    } catch (error){
        console.error(error);
        res.status(500).json({message:"Internal Server Error"});
    }
})

// Insert your user login code here.
app.post("/login",async (req,res)=>{
    const {username, email,password} = req.body;
    try {
        const user = await User.findOne({$or:[{username},{email}]});
        if(!user) {
            return res.status(401).json({message:"Invalid credentials"})
        }
        const token = jwt.sign({userId:user._id,username:user.username},SECRET_KEY,{expiresIn:"1h"});
        req.session.token = token;
        res.redirect(`/index?username=${user.username}`);
    } catch (error) {
        console.error('Error:', error);
    }
})
//get all posts
app.get("/posts",async (req,res)=>{
   const result =  await Post.find();
   res.send(result);
})



// Insert your post creation code here.

app.post("/posts",authenticateJWT,async (req,res)=>{
    const {text} = req.body;
    if(!text || typeof text!== 'string') {
        return res.status(400).json({message:"please provide valid post content"});
    }
    const newPost = new Post({userId: req.user.userId,text}) ;
    await newPost.save();

    res.status(201).json(newPost);
})

// Insert your post updation code here.

app.put("/posts/:postId",authenticateJWT,async (req,res)=>{
    const postId = req.params.postId;
    const post = await Post.findOne( {$and:[{_id:postId},{userId:req.user.userId}] });
    if(!post) return res.status(404).json({message:"Post not found"});
    await Post.updateOne({_id:postId},{text:req.body.text})
    res.json({message:"post updated successfully"});
})

// Insert your post deletion code here.
app.delete("/posts/:postId",authenticateJWT,async (req,res)=>{
    const postId = req.params.postId;
    const post = await Post.findOne( {$and:[{_id:postId},{userId:req.user.userId}] });
    if(!post){
        return res.status(404).json({message:"Post not found"});
    }
    await Post.deleteOne({_id:postId})
    res.json({message:"Post deleted successfully"});
})

// Insert your user logout code here.

app.get("/logout",(req,res)=>{
    req.session.destroy((err)=>{
        if(err) console.err(err);
        res.redirect("/login");
    })
})
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));

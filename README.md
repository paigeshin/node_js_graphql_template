# node_js_graphql_template

# What's In This module?

- What is GraphQL?
- GraphQL vs REST
- How to use GraphQL

# Rest API

- Stateless, client-independent API for exchanging data

# GraphQL API

- Stateless, client-independent API for exchanging data with **higher query flexibility.**
- Only `POST` request

# REST API Limitations

- Very limited in terms of flexibility.

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/529408c9-dd48-4344-a85f-8c606312e2b7/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/529408c9-dd48-4344-a85f-8c606312e2b7/Untitled.png)

# How does GraphQL Work?

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/e4611f49-9fbb-40fa-bca2-9dee1b14961d/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/e4611f49-9fbb-40fa-bca2-9dee1b14961d/Untitled.png)

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/e818d9a6-8d6c-4b99-b62c-1d2e04af82f1/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/e818d9a6-8d6c-4b99-b62c-1d2e04af82f1/Untitled.png)

# Operation Types

- Query → Retrieve Data("GeT")
- Mutation → Manipulate Data ("POST", "PUT", "PATCH", "DELETE")
- Subscription → Set up realtime connection via Websockets

# GrahpQL Big Picture

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/da4918d3-3f72-4957-be0b-448ab78a8ea2/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/da4918d3-3f72-4957-be0b-448ab78a8ea2/Untitled.png)

- **Query Definitions (Type Definition)**
- **Mutation Definitions (Type Definition)**
- **Subscription Definitions  (Type Definition)**

# How does GrapQL Work?

- It's a normal Node (+ Express) Server!
- ONE Single Endpoint (typically/graphql)
- Uses POST because Request Body defines Data Structure of retrieved Data
- Server-side Resolver analyzes Request Body, Fetches and Prepares and Returns Data

# Understanding the Setup & Writing Our First Query

- [https://graphql.org/](https://graphql.org/)

### npm

```bash
npm i --save graphql
npm i --save express-graphql
```

### Set Up on App.js

```jsx
/*** GraphQL ***/
const { graphqlHTTP } = require('express-graphql');
const graphqlSchema = require('./graphql/schema');
const graphqlResolver = require('./graphql/resolvers');

/*** GrpahlQL ***/
app.use('/graphql', graphqlHTTP({
    schema: graphqlSchema,
    rootValue: graphqlResolver,
    graphiql: true //web browser에서 확인 가능하게함
}));
```

### Schema, ./graphql/schema.js  ⇒ 데이터를 정의하는 곳, First Query

```jsx
//get `buildSchema` method from `graphql`
const { buildSchema } = require('graphql');

module.exports = buildSchema(`
    
    type TestData {
        text: String!
        views: Int!
    }
    
    type RootQuery {
        hello: TestData!
    }
 
    schema {
        query: RootQuery
    }
    
`);
```

### Resolver, ./graphql/resolvers.js  ⇒ 데이터를 받아오는 곳

```jsx
module.exports = {
    hello() {
        return {
            text: 'Hello World!',
            views: 1245
        };
    }
};
```

### Query 작성

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/f0f6e825-469e-4d40-b203-24e0517eb9e7/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/f0f6e825-469e-4d40-b203-24e0517eb9e7/Untitled.png)

# Mutation Query

### Schema

```jsx
/*** Mutation Data ***/
module.exports = buildSchema(`

    type Post {
        _id: ID!
        title: String!
        content: String!
        imageUrl: String!
        creator: User!
        createdAt: String!
        updatedAt: String!
    }
    
    type User {
        _id: ID!
        name: String!
        password: String!
        email: String!
        status: String!
        posts: [Post!]!
    }
    
    input UserInputData {
        email: String! 
        name: String!
        password: String!
    }
    
    type RootQuery {
        hello: String
    }
    
    type RootMutation {
        createUser(userInput: UserInputData): User!
    }
    
    schema {
        query: RootQuery
        mutation: RootMutation
    }
        
`);
```

### Resolver

```jsx
/*** Mutation Query Example ***/
module.exports = {
    /*
        input UserInputData {
            email: String!
            name: String!
            password: String!
        }

        type RootMutation {
            createUser(userInput: UserInputData): User!
        }
     */

    /* one option, use `args` object
    args here contain email & name & password, look at schema defined

    createUser(args, req) {
        const email = args.userInput.email;
    }

     */

    /* another option, use `destructuring` */
    createUser: async function( { userInput }, req) {
        //return User.findOne().then()
        const existingUser = await User.findOne({email: userInput.email});
        if(existingUser) {
            const error = new Error('User exists already!');
            throw error;
        }
        const hashedPw = await bcrypt.hash(userInput.password, 12);
        const user = new User({
            email: userInput.email,
            name: userInput.name,
            password: hashedPw
        });
        const createdUser = await user.save();
        return { ...createdUser._doc, _id: createdUser._id.toString() };
    }

};
```

# Make Query to load data

```graphql
mutation {
  createUser(userInput: {email: "Hello", name: "Paige", password: "Tester"}) {
    _id 
    email
  }
}
```

# Node-Express Validator for GraphQL

```bash
npm install --save validator
```

### Back-end, set up error handlings using `validator` package

- Handling Errors, on `app.js` middleware

```jsx
/*** GrpahlQL ***/
app.use('/graphql', graphqlHTTP({
    schema: graphqlSchema,
    rootValue: graphqlResolver,
    graphiql: true, //web browser에서 확인 가능하게함
    formatError(err) { //graphql api
        if(!err.originalError) {
            return err;
        }
        const data = err.originalError.data;
        const message = err.message || 'An error occurred.';
        const code = err.originalError.code || 500;
        return {message: message, status: code, data: data}; //return your own error object
    }
}));
```

- on `resolver`

```jsx
const bcrypt = require('bcryptjs');
const validator = require('validator'); //express-validator와 다르다.

const User = require('../models/user');

/*** Mutation Query Example ***/
module.exports = {

    createUser: async function( { userInput }, req) {

        /*** Validation Logic **/
        const errors = [];
        if(!validator.isEmail(userInput.email)) {
            errors.push({message: 'Email is invalid.'});
        }

        if(validator.isEmpty(userInput.password) || !validator.isLength(userInput.password, { min: 5 })) {
            errors.push({message: 'Password too short!'});
        }

        if (errors.length > 0) {
            const error = new Error('Invalid input.');

            //add new property
            error.data = errors;
            error.code = 422;

            throw error;
        }

        const existingUser = await User.findOne({email: userInput.email});
        if(existingUser) {
            throw new Error('User exists already!');
        }
        const hashedPw = await bcrypt.hash(userInput.password, 12);
        const user = new User({
            email: userInput.email,
            name: userInput.name,
            password: hashedPw
        });
        const createdUser = await user.save();
        return { ...createdUser._doc, _id: createdUser._id.toString() };
    }

};
```

### Front-end Part에서 query 작성

- query를 key 값으로 주고 나머지는 똑같이 사용하면 된다. (webbrowser에서 확인한 데이터)

```jsx
/* Front-End GraphQL */
//query를 key값으로 주고 나머지는 똑같이 사용하면 된다.
const graphqlQuery = {
  query: `
      mutation {
        createUser(userInput: {
          email: "${authData.signupForm.email.value}", 
          name: "${authData.signupForm.name.value}", 
          password: "${authData.signupForm.password.value}"}) {
          _id 
          email
        }
      }
  `
};
```

- error handling

```jsx
//graphql Error Handling
if(resData.errors && status.errors[0].status === 422) {
    throw new Error(
      "Validation failed. Make sure the email address isn't used yet!"
    )
}
if(resData.errors) {
    throw new Error('User creation failed!');
}
```

### Backend

- `req.method === 'OPTIONS'` means `get, post, put, delete.....` but it Graphql you can only use `POST`. So other options are denied.
- Therefore, you need to send empty response for the status code.

```jsx
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader(
    'Access-Control-Allow-Methods',
    'OPTIONS, GET, POST, PUT, PATCH, DELETE'
  );
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  //OPTIONS Means `get,post,put,delete....` but in Graphql you can only use `POST` so other options are denied.
  //Therefore, you need to send empty response for the status code.
  if(req.method === 'OPTIONS'){
      return res.sendStatus(200); //it stops here by sending `empty status`
  }
  next();
});
```

# Add Login Query

- add login  `Root Query` schema

```jsx
module.exports = buildSchema(`
		type AuthData {
		    token: String!
		    userId: String!
		}
		
		type RootQuery {
		   login(email: String!, password: String!): AuthData!
		}
`)
```

- resolver

```jsx
/*** Mutation Query Example ***/
module.exports = {
    login: async function({ email, password }) {
        const user = await User.findOne({email: email});
        if(!user) {
            const error = new Error('User not found.');
            error.code = 401;
            throw error;
        }
        const isEqual = await bcrypt.compare(password, user.password);
        if (!isEqual) {
            const error = new Error('Password is incorrect.');
            error.code = 401;
            throw error;
        }

        //encode token with userId and email
        const token = jwt.sign({
            userId: user._id.toString(),
            email: user.email
        }, 'somesecret', {expiresIn: '1h'});
        return { token: token,  userId: user._id.toString() } //return values must be the same
    }
};
```

- token generation

```jsx
//encode token with userId and email
const token = jwt.sign({
    userId: user._id.toString(),
    email: user.email
}, 'somesecret', {expiresIn: '1h'});
return { token: token,  userId: user._id.toString() } //return values must be the same
```

  

![https://s3-us-west-2.amazonaws.com/secure.notion-static.com/eebbd646-b80f-4682-9cd4-84a2b341640e/Untitled.png](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/eebbd646-b80f-4682-9cd4-84a2b341640e/Untitled.png)

⇒ Graphql에서 default로 `data` field가 생성된다.

⇒ 항상 웹사이트에서 데이터 format이 어떻게 날라오는지 확인하는게 좋다.

- front-end logic
- 패턴 분석

```jsx
loginHandler = (event, authData) => {
    event.preventDefault();
	
		//query 만들기
    const graphqlQuery = {
      query: `
        {
          login(email: "${authData.email}", password: ${authData.password}) {
            token
            userId
          }
        }
      `
    }

    this.setState({ authLoading: true });
    fetch('http://localhost:8080/graphql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(graphqlQuery)
    })
      .then(res => {
        return res.json();
      })
      .then(resData => {
        if(resData.errors && resData.errors[0].status === 422) {
          throw new Error(
            "Validation failed. Make sure the email address isn't used yet!"
          );
        }
        if(resData.errors) {
          throw new Error('User login failed!');
        }
        console.log(resData);
        this.setState({
          isAuth: true,
          token: resData.data.login.token,
          authLoading: false,
          userId: resData.data.login.userId
        });
        localStorage.setItem('token', resData.data.login.token);
        localStorage.setItem('userId', resData.data.login.userId);
        const remainingMilliseconds = 60 * 60 * 1000;
        const expiryDate = new Date(
          new Date().getTime() + remainingMilliseconds
        );
        localStorage.setItem('expiryDate', expiryDate.toISOString());
        this.setAutoLogout(remainingMilliseconds);
      })
      .catch(err => {
        console.log(err);
        this.setState({
          isAuth: false,
          authLoading: false,
          error: err
        });
      });
  };
```

- query 만들기

```jsx
//query 만들기
const graphqlQuery = {
  query: `
    {
      login(email: "${authData.email}", password: ${authData.password}) {
        token
        userId
      }
    }
  `
}
```

- data 가져오기

⇒ JSON.stringfy(graphqlQuery) , body parameters to be sent

⇒ res.json(), 다시 json 화

```jsx
this.setState({ authLoading: true });
fetch('http://localhost:8080/graphql', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify(graphqlQuery)
})
.then(res => {
  return res.json();
})

```

# Adding a Create Post Mutation

- query definition

⇒ type 정의

⇒ inputData 정의

⇒ RootMutation에 함수 정의

```jsx
module.exports = buildSchema(`

    type Post {
        _id: ID!
        title: String!
        content: String!
        imageUrl: String!
        creator: User!
        createdAt: String!
        updatedAt: String!
    }
		
		input PostInputData {
        title: String!
        content: String!
        imageUrl: String!
    }

		type RootMutation {
        createUser(userInput: UserInputData): User!
        createPost(postInput: PostInputData): Post!
    }

`)
```

- resolver - 함수 정의

```jsx
/*** Mutation Query Example ***/
module.exports = {
    createPost: async function({ postInput }, req) {
        const errors = [];
        if(validator.isEmpty(postInput.title) || !validator.isLength(postInput.title, { min: 5 })) {
            errors.push({message: 'Title is invalid.'});
        }
        if(validator.isEmpty(postInput.content) || !validator.isLength(postInput.content, { min: 5 })) {
            errors.push({message: 'Content is invalid.'});
        }
        if(errors.length > 0) {
            const error = new Error('Invalid input.');
            error.data = errors;
            error.code = 422;
            throw error;
        }
        const post = new Post({
            title: postInput.title,
            content: postInput.content,
            imageUrl: postInput.imageUrl
        });
        const createdPost = await post.save();
        // Add Post to users' posts
        return {...createdPost._doc, _id: createdPost._id.toString(), createdAt: createdPost.createdAt.toISOString(), updatedAt: createdPost.updatedAt.toISOString()};
    }

};
```

- tweaking /middleware/auth.js

```jsx
const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
    const authHeader = req.get('Authorization');
    //Previous Code
    // if (!authHeader) {
    //     const error = new Error('Not authenticated.');
    //     error.statusCode = 401;
    //     throw error;
    // }

    //Changed Code, why? => to handle where there's no header
    //If there's no header, stop proceeding.
    if(!authHeader) {
        req.isAuth = false;
        return next();
    }

    const token = authHeader.split(' ')[1];
    let decodedToken;
    try {
        decodedToken = jwt.verify(token, 'somesupersecretsecret');
    } catch (err) {

        //previous code
        // err.statusCode = 500;
        // throw err;

        //changed code, why? => to handle where there's no header
        req.isAuth = false;
        return next();
    }
    if (!decodedToken) {
        //previous code
        // const error = new Error('Not authenticated.');
        // error.statusCode = 401;
        // throw error;

        //changed code, why? => to handle when there's no header
        req.isAuth = false;
        return next();
    }

    req.userId = decodedToken.userId;
    //added code
    req.isAuth = true;
    next();
};
```

- add changed middleware on `app.js`

```jsx
const auth = require('./middleware/auth');

app.use(auth);

/*** GrpahlQL ***/
app.use('/graphql', graphqlHTTP({
    schema: graphqlSchema,
    rootValue: graphqlResolver,
    graphiql: true, //web browser에서 확인 가능하게함
    formatError(err) { //graphql api
        console.log("formatError called!");
        console.log(`err.originalError: ${err.originalError}`);
        if (!err.originalError) {
            return err;
        }
        const data = err.originalError.data;
        const message = err.message || 'An error occurred.';
        const code = err.originalError.code || 500;
        return {message: message, status: code, data: data}; //return your own error object
    }
}));
```

- refactored code with `req.isAuth`

```jsx
const bcrypt = require('bcryptjs');
const validator = require('validator'); //express-validator와 다르다.

const jwt = require('jsonwebtoken');
const User = require('../models/user');
const Post = require('../models/post');

/*** Mutation Query Example ***/
module.exports = {

    createPost: async function({ postInput }, req) {

        //applied error handling when there's no header or token is invalid
        if(!req.isAuth) {
            const error = new Error('Not authenticated!');
            error.code = 401;
            throw error;
        }

        const errors = [];
        if(validator.isEmpty(postInput.title) || !validator.isLength(postInput.title, { min: 5 })) {
            errors.push({message: 'Title is invalid.'});
        }
        if(validator.isEmpty(postInput.content) || !validator.isLength(postInput.content, { min: 5 })) {
            errors.push({message: 'Content is invalid.'});
        }
        if(errors.length > 0) {
            const error = new Error('Invalid input.');
            error.data = errors;
            error.code = 422;
            throw error;
        }

        //added code
        const user = await User.findById(req.userId);
        if(!user) {
            const error = new Error('Invalid user.');
            error.code = 401;
            throw error;
        }
        const post = new Post({
            title: postInput.title,
            content: postInput.content,
            imageUrl: postInput.imageUrl,
            creator: user
        });
        const createdPost = await post.save();
        //set up connection, added code
        user.posts.push(createdPost);

        // Add Post to users' posts
        return {...createdPost._doc, _id: createdPost._id.toString(), createdAt: createdPost.createdAt.toISOString(), updatedAt: createdPost.updatedAt.toISOString()};
    }

};
```

- client code

⇒ advanced query

- 패턴분석

```jsx
let graphqlQuery = {
      query: `
        mutation {
          createPost(postInput: {title: "${postData.title}", content: "${postData.content}", imageUrl: "some url"}) {
            _id
            title
            content
            imageUrl
            creator {
              name
            }
            createdAt
          }
        }
      `
    };
```

`creator { name }` ⇒ 여기서 creator은 `User` object인데, 거기서 원하는 data만 추출하려면 다시 curly brace로 원하는 데이터 field 이름을 적어주기만 하면 된다.

⇒ post 

```jsx
finishEditHandler = postData => {
    this.setState({
      editLoading: true
    });
    const formData = new FormData();
    formData.append('title', postData.title);
    formData.append('content', postData.content);
    formData.append('image', postData.image);

    let graphqlQuery = {
      query: `
        mutation {
          createPost(postInput: {title: "${postData.title}", content: "${postData.content}", imageUrl: "some url"}) {
            _id
            title
            content
            imageUrl
            creator {
              name
            }
            createdAt
          }
        }
      `
    };

    fetch('http://127.0.0.1:8080/graphql', {
      method: 'POST',
      body: JSON.stringify(graphqlQuery),
      headers: {
        Authorization: 'Bearer ' + this.props.token,
        'Content-Type': 'application/json'
      }
    })
      .then(res => {
        return res.json();
      })
      .then(resData => {
        if(resData.errors && resData.errors[0].status === 422) {
          throw new Error(
              "Validation failed. Make sure the email address isn't used yet!"
          );
        }
        if(resData.errors) {
          throw new Error('User login failed!');
        }
        console.log(resData);
        const post = {
          _id: resData.data.createPost._id,
          title: resData.data.createPost.title,
          content: resData.data.createPost.content,
          creator: resData.data.createPost.creator,
          createdAt: resData.data.createPost.createdAt
        };
        this.setState(prevState => {
          return {
            isEditing: false,
            editPost: null,
            editLoading: false
          };
        });
      })
      .catch(err => {
        console.log(err);
        this.setState({
          isEditing: false,
          editPost: null,
          editLoading: false,
          error: err
        });
      });
  };
```

# Get posts

### Define Query

- totalPosts를 보내는 이유는, pagination 때문이다.

```jsx
module.exports = buildSchema(`
		type PostData {
		    posts: [Post!]!
		    totalPosts: Int!
		}
		
		type RootQuery {
       posts: PostData!
    }
`)
```

⇒ Parameter가 없는 function

- resolver

```jsx
module.exports = (req, res, next) => {
posts: async function(args, req) {
	    //if request is not authenticated, throw error
	    if(!req.isAuth) {
	        const error = new Error('Not authenticated!');
	        error.code = 401;
	        throw error;
	    }
	
	    const totalPosts = await Post.find().countDocuments();
	    const posts = await Post.find()
	        .sort({createdAt: -1})
	        .populate('creator');
	    return { posts: posts.map(p => {
	            return {...p._doc,
	                _id: p._id.toString(),
	                createdAt: p.createdAt.toISOString(),
	                updatedAt: p.updatedAt.toISOString()
	            };
	        }),
	        totalPosts: totalPosts
	    };
	}
}
```

- get data

```graphql
query {
  posts {
    posts {
      _id
      title
      content
    }
    totalPosts
  }
}
```

# Sending "Create Post" and "Get Post" Queries

- Front-end Javascript
- 패턴 분석

```jsx
loadPosts = direction => {
    if (direction) {
      this.setState({ postsLoading: true, posts: [] });
    }
    let page = this.state.postPage;
    if (direction === 'next') {
      page++;
      this.setState({ postPage: page });
    }
    if (direction === 'previous') {
      page--;
      this.setState({ postPage: page });
    }

    const graphqlQuery = {
      query: `
        {
          posts {
            posts {
              _id
              title
              content
              creator {
                name
              }
              createdAt
            }
            totalPosts
          } 
        }
      `
    };

    fetch('http://127.0.0.1:8080/graphql', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + this.props.token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(graphqlQuery)
    })
      .then(res => {
        return res.json();
      })
      .then(resData => {
        if(resData.errors) {
          throw new Error('Fetching posts failed!');
        }
        this.setState({
          posts: resData.data.posts.posts.map(post => {
            return {
              ...post,
              imagePath: post.imageUrl
            };
          }),
          totalPosts: resData.data.posts.totalPosts,
          postsLoading: false
        });
      })
      .catch(this.catchError);
  };
```

# Implement Pagination

```jsx
module.exports = buildSchema(`

		type PostData {
		    posts: [Post!]!
		    totalPosts: Int!
		}
		  
		type RootQuery {
		   posts(page: Int): PostData!
		}

`)
```

- front-end application , update query with `page` parameter

```jsx
const graphqlQuery = {
      query: `
        {
          posts(${page}) {
            posts {
              _id
              title
              content
              creator {
                name
              }
              createdAt
            }
            totalPosts
          } 
        }
      `
    };
```

- load post, entire code
- 패턴 분석

```jsx
loadPosts = direction => {
    if (direction) {
      this.setState({ postsLoading: true, posts: [] });
    }
    let page = this.state.postPage;
    if (direction === 'next') {
      page++;
      this.setState({ postPage: page });
    }
    if (direction === 'previous') {
      page--;
      this.setState({ postPage: page });
    }
    const graphqlQuery = {
      query: `
        {
          posts(page: ${page}) {
            posts {
              _id
              title
              content
              creator {
                name
              }
              createdAt
            }
            totalPosts
          }
        }
      `
    };
    fetch('http://localhost:8080/graphql', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + this.props.token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(graphqlQuery)
    })
      .then(res => {
        return res.json();
      })
      .then(resData => {
        if (resData.errors) {
          throw new Error('Fetching posts failed!');
        }
        this.setState({
          posts: resData.data.posts.posts.map(post => {
            return {
              ...post,
              imagePath: post.imageUrl
            };
          }),
          totalPosts: resData.data.posts.totalPosts,
          postsLoading: false
        });
      })
      .catch(this.catchError);
  };
```

# Fetching the imageUrl, uploading images

- back-end code

⇒ set up a router. (REST API) 

⇒ You can always add router if needed.

```jsx
//file handling, how to handle file on graphql server
//Create Restful API for handling files
app.put('/post-image', (req, res, next) => {
    if(!req.isAuth) {
        throw new Error('Not authenticated!');
    }
    //file이 없다면....
    if(!req.file) { //multer가 설치되어있다면 항상 req.file에 접근할 수 있다.
        return res.status(200).json({message: 'No file provided!'});
    }
    if (req.body.oldPath) { //이전 파일 이름이라면
        clearImage(req.body.oldPath); //서버에서 파일을 삭제해준다.
    }
    return res.status(201).json({message: 'File stored.', filePath: req.file.path});
});
```

- front-end code
- 패턴분석

❗️Note that, files are binary data. If you set `application/json` , it will be automatically parsed into JSON, making errors.

```jsx
fetch('http://127.0.0.1:8080/post-image', {
      method: 'PUT',
      headers: {
        Authorization: 'Bearer ' + this.props.token
        //'Content-Type': 'application/json'           //file data is binary data, if you set `Content-Type: application/json` it will be parsed as JSON data. it won't work. 
      },
      body: formData
    })
    .then(res => res.json())
    .then(fileResData => {
        const imageUrl = fileResData.filePath;
        let graphqlQuery = {
          query: `
            mutation {
              createPost(postInput: {title: "${postData.title}", content: "${
            postData.content
          }", imageUrl: "${imageUrl}"}) {
                _id
                title
                content
                imageUrl
                creator {
                  name
                }
                createdAt
              }
            }
          `
        };
```

# Fetch single post

```jsx
const { buildSchema } = require('graphql'); //get `buildSchema` method from `graphql`

/*** Mutation Data ***/
module.exports = buildSchema(`

    type Post {
        _id: ID!
        title: String!
        content: String!
        imageUrl: String!
        creator: User!
        createdAt: String!
        updatedAt: String!
    }
    
    type RootQuery {
       login(email: String!, password: String!): AuthData!
       posts(page: Int): PostData!
       post(id: ID!): Post! 
    }
    
    schema {
        query: RootQuery
        mutation: RootMutation
    }
        
`);
```

- resolver

```jsx
const bcrypt = require('bcryptjs');
const validator = require('validator'); //express-validator와 다르다.

const jwt = require('jsonwebtoken');
const User = require('../models/user');
const Post = require('../models/post');

/*** Mutation Query Example ***/
module.exports = {
		//get single post
    post: async function({id}, req) {
        if (!req.isAuth) {
            const error = new Error('Not authenticated!');
            error.code = 401;
            throw error;
        }
        const post = await Post.findById(id).populate('creator');
        if(!post) {
            const error = new Error('No post found!');
            error.code = 404;
            throw error;
        }
        return {
            ...post._doc,
            _id: post._id.toString(),
            createdAt: post.createdAt.toISOString(),
            updatedAt: post.updatedAt.toISOString()
        }
    }
}
```

# Update Post

- schema

```jsx
type Post {
    _id: ID!
    title: String!
    content: String!
    imageUrl: String!
    creator: User!
    createdAt: String!
    updatedAt: String!
}

input PostInputData {
    title: String!
    content: String!
    imageUrl: String!
}

type RootMutation {
    updatePost(id: ID!, postInput: PostInputData): Post!
}
```

- resolver

```jsx
//updatePost
  updatePost: async function({ id, postInput }, req) {
      if (!req.isAuth) {
          const error = new Error('Not authenticated!');
          error.code = 401;
          throw error;
      }
      const post = await Post.findById(id).populate('creator');
      if (!post) {
          const error = new Error('No post found!');
          error.code = 404;
          throw error;
      }
      if (post.creator._id.toString() !== req.userId.toString()) {
          const error = new Error('Not authorized!');
          error.code = 403;
          throw error;
      }
      const errors = [];
      if (
          validator.isEmpty(postInput.title) ||
          !validator.isLength(postInput.title, { min: 5 })
      ) {
          errors.push({ message: 'Title is invalid.' });
      }
      if (
          validator.isEmpty(postInput.content) ||
          !validator.isLength(postInput.content, { min: 5 })
      ) {
          errors.push({ message: 'Content is invalid.' });
      }
      if (errors.length > 0) {
          const error = new Error('Invalid input.');
          error.data = errors;
          error.code = 422;
          throw error;
      }
      post.title = postInput.title;
      post.content = postInput.content;
      if (postInput.imageUrl !== 'undefined') {
          post.imageUrl = postInput.imageUrl;
      }
      const updatedPost = await post.save();
      return {
          ...updatedPost._doc,
          _id: updatedPost._id.toString(),
          createdAt: updatedPost.createdAt.toISOString(),
          updatedAt: updatedPost.updatedAt.toISOString()
      };
  }
```

# Delete Post

### Backend

- schema

```jsx
const { buildSchema } = require('graphql'); //get `buildSchema` method from `graphql`

/*** Mutation Data ***/
module.exports = buildSchema(`

    type RootMutation {
        deletePost(id: ID!): Boolean
    }
    
    schema {
        query: RootQuery
        mutation: RootMutation
    }
        
`)
```

- resolver

```jsx
const bcrypt = require('bcryptjs');
const validator = require('validator'); //express-validator와 다르다.

const jwt = require('jsonwebtoken');
const User = require('../models/user');
const Post = require('../models/post');
const { clearImage } = require('../util/file');

/*** Mutation Query Example ***/
module.exports = {

    deletePost: async function({id}, req) {
        //if isAuth set to be false, it means token is not valid
        if (!req.isAuth) {
            const error = new Error('Not authenticated!');
            error.code = 401;
            throw error;
        }
        const post = await Post.findById(id);

        //Check if post exists
        if(!post) {
            const error = new Error('No post found!');
            error.code = 404;
            throw error;
        }

        //Check if the post belongs to user.
        //req.userId is saved in the /middleware/auth.js from decoded token
        //here, creator itself is id, because we saved it in the database in that way.
        if(post.creator.toString() !== req.userId.toString()) {
            const error = new Error('Not authorized!');
            error.code = 403;
            throw error;
        }
        clearImage(post.imageUrl); //path of the image on my server
        await Post.findByIdAndRemove(id);
        const user = await User.findById(req.userId);
        //nested id가 document 내부에 존재하는 경우 `pull`을 사용해야 한다.
        //각 유저에는 postId를 담은 array가 존재하는데, 거기서 값을 지워주는 것이다
        user.posts.pull(id); //delete nested `id` in the post
        await user.save();
        return true;
    }

};
```

### Frontend

- 패턴 분석

```jsx
const graphQuery = {
      query: `
        mutation {
          deletePost(id: "${postId}")
        }
      `
    }
    fetch('http://localhost:8080/graphql', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + this.props.token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(graphQuery)
    })
      .then(res => {
        return res.json();
      })
      .then(resData => {
        if(resData.errors) {
          throw new Error('User login failed!');
        }
        console.log(resData);
        this.loadPosts();
        // this.setState(prevState => {
        //   const updatedPosts = prevState.posts.filter(p => p._id !== postId);
        //   return { posts: updatedPosts, postsLoading: false };
        // });
      })
      .catch(err => {
        console.log(err);
        this.setState({ postsLoading: false });
      });
  };
```

# Function Export

/util/file.js

```jsx
/*** file.js is for handling file-related operations ***/
const path = require('path');
const fs = require('fs');

const clearImage = filePath => {
    filePath = path.join(__dirname, '..', filePath);
    fs.unlink(filePath, err => console.log(err));
};

//export function
exports.clearImage = clearImage;
```

app.js

```jsx
//get function from file.js, using destructuring
const { clearImage } = require('./util/file');
```

# Managing the User Status

### backend - user, updateStatus

schema.js

```jsx
const { buildSchema } = require('graphql'); //get `buildSchema` method from `graphql`

/*** Mutation Data ***/
module.exports = buildSchema(`

    type User {
        _id: ID!
        name: String!
        password: String!
        email: String!
        status: String!
        posts: [Post!]!
    }
    
    type RootQuery {
	      user: User!
    }
    
    type RootMutation {
        updateStatus(status: String): User!
    }
    
    schema {
        query: RootQuery
        mutation: RootMutation
    }
        
`);
```

⇒ user:User!, 아무 parameter가 없는 함수 

resolver.js

```jsx
user: async function(args, req) {
        //if isAuth set to be false, it means token is not valid
        if (!req.isAuth) {
            const error = new Error('Not authenticated!');
            error.code = 401;
            throw error;
        }
        const user = await User.findById(req.userId);
        if(!user) {
            const error = new Error('No post found!');
            error.code = 404;
            throw error;
        }
        return {...user._doc, _io: user._id.toString()};
    }
```

### Front-end, - user

- 패턴 분석

```jsx
const graphqlQuery = {
      query: `
        {
          user {
            status
          }
        }
      `
	  };

fetch('http://localhost:8080/graphql', {
  method: 'POST',  
  headers: {
      Authorization: 'Bearer ' + this.props.token,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(graphqlQuery)
  })
  .then(res => {
    return res.json();
  })
  .then(resData => {
    if(resData.errors) {
      throw new Error('Fetching status failed!');
    }
    this.setState({ status: resData.data.user.status });
  })
  .catch(this.catchError);
```

### Back-end, resolver, updateStatus

```jsx
updateStatus: async function({status}, req) {
    if(!req.isAuth) {
        const error = new Error('Not authenticated!');
        error.code = 401;
        throw error;
    }
    const user = await User.findById(req.userId);
    if(!user) {
        const error = new Error('No post found!');
        error.code = 404;
        throw error;
    }
    user.status = status;
    await user.save();
    return {...user._doc, _id: user._id.toString()}
}
```

### Front-end, updateStatus

```jsx
statusUpdateHandler = event => {
    event.preventDefault();
    const graphqlQuery = {
      query: `
        mutation {
          updateStatus(status: "${this.state.status}"){
            status
          }
        }
      `
    };
    fetch('http://localhost:8080/graphql', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + this.props.token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(graphqlQuery)
    })
      .then(res => {
        return res.json();
      })
      .then(resData => {
        if (resData.errors) {
          throw new Error('Updating status failed!');
        }
        console.log(resData);
      })
      .catch(this.catchError);
  };
```

# Better way to write graphql query - front-end

- before being refactored

```jsx
//Before being refacotored
  
const graphqlQuery = {
  query: `
    {
      posts(page: ${page}) {
        posts {
          _id
          title
          content
          creator {
            name
          }
          createdAt
        }
        totalPosts
      }
    }
  `
};
    
```

- after being refactored

```jsx
//After being refactored
const graphqlQuery = {
  //함수처럼 이름을 넣을 수 있다.
  query: `
    query FetchPosts($page: Int) {
      posts(page: $page) {
        posts {
          _id
          title
          content
          imageUrl
          creator {
            name
          }
          createdAt
        }
        totalPosts
      }
    }
  `,
  //위에서 정의한 $page의 변수를 넘겨준다
  variables: {
      page: page
  }
}
```

- Before being refactored

```jsx
const graphqlQuery = {
      query: `
        mutation {
          updateStatus(status: "${this.state.status}"){
            status
          }
        }
      `
    };
```

- After being refactored

```jsx
const graphqlQuery = {
      query: `
        mutation UpdateUserStatus($userStatus: String!) {
          updateStatus(status: $userStatus) {
            status
          }
        }
      `,
      variables: {
        userStatus: this.state.status
      }
    }
```

- Before being refactored

```jsx
let graphqlQuery = {
  query: `
	  mutation {
	    createPost(postInput: {title: "${postData.title}", content: "${
	    postData.content
	  }", imageUrl: "${imageUrl}"}) {
	      _id
	      title
	      content
	      imageUrl
	      creator {
	        name
	      }
	      createdAt
	    }
	  }
	`
};
```

- After being refactored

```jsx
let graphqlQuery = {
  query: `
    mutation CreateNewPost($title: String!, $content: String!, $imageUrl: String!) {
      createPost(postInput: {title: $title, content: $content, imageUrl: $imageUrl}) {
        _id
        title
        content
        imageUrl
        creator {
          name
        }
        createdAt
      }
    }
  `,
  variables: {
      title: postData.title, 
      content: postData.content,
      imageUrl: imageUrl
  }
};
```

- Before being refactored

```jsx
graphqlQuery = {
		query: `
		  mutation {
		    updatePost(id: "${this.state.editPost._id}", postInput: {title: "${postData.title}", content: "${
		    postData.content
		  }", imageUrl: "${imageUrl}"}) {
		      _id
		      title
		      content
		      imageUrl
		      creator {
		        name
		      }
		      createdAt
		    }
		  }
		`
```

- After being refactored

```jsx
graphqlQuery = {
  query: `
    mutation UpdateExistingPost($postId: ID!, $title: String!, $content: String!, $imageUrl: String!) {
      updatePost(id: $postId, postInput: {title: $title, content: $content, imageUrl: $imageUrl}) {
        _id
        title
        content
        imageUrl
        creator {
          name
        }
        createdAt
      }
    }
  `,
  variables: {
    posdId: this.state.editPost._id,
    title: postData.title, 
    content: postData.content,
    imageUrl: postData.imageUrl
  }
};
```

❗️`!`는 graphql에서 required data field라느 의미다

- single post query refactored

```jsx
const graphqlQuery = {
      query: `query FetchSinglePost($postId: ID!) {
          post(id: $postId) {
            title
            content
            imageUrl
            creator {
              name
            }
            createdAt
          }
        }
      `,
      variables: {
        postId: postId
      }
    };
```

- login query

```jsx
const graphqlQuery = {
      query: `
        query UserLogin($email: String!, $password: String!){
          login(email: $email, password: $password) {
            token
            userId
          }
        }
      `,
      variables: {
        email: authData.email,
        password: authData.password
      }
    };
```

- signup query

```jsx
const graphqlQuery = {
      query: `
        mutation CreateNewUser($email: String!, $name: String!, $password: String!) {
          createUser(userInput: {email: $email, name: $name, password: $password}) {
            _id
            email
          }
        }
      `,
      variables: {
        email: authData.signupForm.email.value,
        name: authData.signupForm.name.value,
        password: authData.signupForm.password.value
      }
    };
```

# Module Summary

### GraphQL Core Concepts

- Stateless, client-independent API
- Higher flexibility that REST APIs offer due to custom query language that is exposed to the client
- Queries (GET),  Mutation (POST, PUT, PATCH, DELETE) and Subscriptions can be used to exchange and manage data
- ALL GraphQL request are directed to ONE endpoint (POST/graphql)
- The server parses the incoming query expression (typically done by third-party packages) and calls the appropriate resolvers
- GraphQL is NOT limited to React.js applications.

### GraphQL vs REST

- REST APIs are great for static data requirements (e.g. file upload, scenarios where you need the same data all the time)
- GraphQL gives you higher flexibility by exposing a full query language to the client
- Both REST and GraphQL APIs can be implemented with ANY framework and actually even with ANY server-side lanugugage
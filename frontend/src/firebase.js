import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";

// Your web app's Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyCqWNZTcf29g-Jc4WCXvynIo1_PSeHrq6Q",
  authDomain: "email-poc-9641c.firebaseapp.com",
  projectId: "email-poc-9641c",
  storageBucket: "email-poc-9641c.firebasestorage.app",
  messagingSenderId: "454097541183",
  appId: "1:454097541183:web:14faec8b1532eb314e808a"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Export auth (THIS is what we use)
export const auth = getAuth(app);

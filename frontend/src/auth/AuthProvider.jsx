import { createContext, useContext, useEffect, useState } from "react";
import {
  auth,
  createUserWithEmailAndPassword,
  googleProvider,
  hasFirebaseConfig,
  onAuthStateChanged,
  signInWithEmailAndPassword,
  signInWithPopup,
  signOut,
} from "../lib/firebase";

const AuthContext = createContext(null);

function formatAuthError(error) {
  const code = error?.code || "";

  if (code === "auth/invalid-credential") {
    return "The email or password is incorrect.";
  }
  if (code === "auth/account-exists-with-different-credential") {
    return "This email is already connected to another sign-in method.";
  }
  if (code === "auth/popup-closed-by-user") {
    return "The Google sign-in popup was closed before authentication completed.";
  }
  if (code === "auth/popup-blocked") {
    return "The browser blocked the Google popup. Allow popups and try again.";
  }
  if (code === "auth/unauthorized-domain") {
    return "This domain is not authorized in Firebase Authentication settings.";
  }
  if (code === "auth/invalid-api-key") {
    return "The Firebase web app API key is invalid.";
  }
  if (code === "auth/user-not-found") {
    return "No account exists for that email.";
  }
  if (code === "auth/weak-password") {
    return "The password must be at least 6 characters long.";
  }
  if (code === "auth/email-already-in-use") {
    return "An account already exists for that email address.";
  }

  return error?.message || "Authentication failed. Check your Firebase configuration and try again.";
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState("");
  const [loading, setLoading] = useState(true);
  const [authError, setAuthError] = useState("");
  const [authBusy, setAuthBusy] = useState("");

  useEffect(() => {
    if (!auth) {
      setLoading(false);
      return undefined;
    }

    const unsubscribe = onAuthStateChanged(auth, async (nextUser) => {
      setUser(nextUser);
      setToken(nextUser ? await nextUser.getIdToken() : "");
      setLoading(false);
    });

    return unsubscribe;
  }, []);

  async function loginWithGoogle() {
    if (!auth || !googleProvider) {
      setAuthError("Firebase web config is missing in the frontend environment.");
      return false;
    }

    setAuthError("");
    setAuthBusy("google");

    try {
      const result = await signInWithPopup(auth, googleProvider);
      setUser(result.user);
      setToken(await result.user.getIdToken());
      return true;
    } catch (error) {
      setAuthError(formatAuthError(error));
      return false;
    } finally {
      setAuthBusy("");
    }
  }

  async function loginWithEmail(email, password) {
    if (!auth) {
      setAuthError("Firebase web config is missing in the frontend environment.");
      return false;
    }

    setAuthError("");
    setAuthBusy("email");

    try {
      const result = await signInWithEmailAndPassword(auth, email, password);
      setUser(result.user);
      setToken(await result.user.getIdToken());
      return true;
    } catch (error) {
      setAuthError(formatAuthError(error));
      return false;
    } finally {
      setAuthBusy("");
    }
  }

  async function registerWithEmail(email, password) {
    if (!auth) {
      setAuthError("Firebase web config is missing in the frontend environment.");
      return false;
    }

    setAuthError("");
    setAuthBusy("signup");

    try {
      const result = await createUserWithEmailAndPassword(auth, email, password);
      setUser(result.user);
      setToken(await result.user.getIdToken());
      return true;
    } catch (error) {
      setAuthError(formatAuthError(error));
      return false;
    } finally {
      setAuthBusy("");
    }
  }

  async function logout() {
    if (!auth) {
      setUser(null);
      setToken("");
      return;
    }
    await signOut(auth);
    setUser(null);
    setToken("");
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        loading,
        authError,
        authBusy,
        hasFirebaseConfig,
        loginWithGoogle,
        loginWithEmail,
        registerWithEmail,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}

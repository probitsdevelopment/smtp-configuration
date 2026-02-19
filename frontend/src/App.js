import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Email from "./pages/Email";

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Navigate to="/email" replace />} />
        <Route path="/email" element={<Email />} />
      </Routes>
    </Router>
  );
}

export default App;

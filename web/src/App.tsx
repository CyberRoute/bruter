import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Layout } from "./components/Layout";
import { Dashboard } from "./pages/Dashboard";
import { Subdomains } from "./pages/Subdomains";
import { Whois } from "./pages/Whois";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="subdomains" element={<Subdomains />} />
          {/* Keep the old /ssl path working as an alias for existing links. */}
          <Route path="ssl" element={<Subdomains />} />
          <Route path="whois" element={<Whois />} />
          <Route path="*" element={<Dashboard />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

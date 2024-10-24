import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useLocation } from 'react-router-dom';
// import { useParams } from 'react-router-dom';

function Vendors() {
  const [vendors, setVendors] = useState([]);
  const [selectedVendors, setSelectedVendors] = useState([]);
  const location = useLocation();

  useEffect(() => {
    const accessToken = new URLSearchParams(location.search).get('accessToken');
    axios.get(`http://127.0.0.1:5000/users?role=vendor`, { headers: { Authorization: `Bearer ${accessToken}` }})
      .then(response => {
        if (response.data.success) {
          console.log("line 16");
          console.log(response.data.users);
          setVendors(response.data.users);
        } else {
          console.log("line 20");
          console.log(response.data.message);
        }
      })
      .catch(error => {
        console.log(error);
      });
  }, []);

  const handleCheckboxChange = (event) => {
    const vendorUsername = event.target.value; // Use username
  
    if (event.target.checked) {
      setSelectedVendors((prevSelected) => [...prevSelected, vendorUsername]); // Store usernames
    } else {
      setSelectedVendors((prevSelected) =>
        prevSelected.filter((username) => username !== vendorUsername)
      );
    }
  };
  
  
  useEffect(() => {
    console.log('Selected Vendors Updated:', selectedVendors);
  }, [selectedVendors]);

  const handleAssignClick = () => {
    const tender_id = new URLSearchParams(location.search).get('tender_id');
    const accessToken = new URLSearchParams(location.search).get('accessToken');
  
    // Check if tender_id or accessToken is missing
    if (!tender_id || !accessToken) {
      alert('Missing required parameters.');
      return;
    }
  
    console.log('Selected vendors:', selectedVendors); // For debugging
  
    // Send the usernames as vendor_ids
    axios.post(
      'http://127.0.0.1:5000/tenders/assign',
      {
        tender_id: tender_id,
        vendor_ids: selectedVendors, // Directly use selectedVendors (usernames)
      },
      { headers: { Authorization: `Bearer ${accessToken}` } }
    )
      .then((response) => {
        alert(response.data.message);
        if (response.data.status === 'success') {
          setSelectedVendors([]); // Clear selection on success
        }
      })
      .catch((error) => {
        alert('Failed to assign vendors. Please try again.');
        console.error(error);
      });
  };
  
  

  const handlePopupClose = () => {
      window.close(); // Close the current window
  };

  return (
    <div>
      <h1>Vendors</h1>
      <button onClick={handleAssignClick}>Assign</button>
      <button onClick={handlePopupClose}>Close</button>
      <table border="2">
        <thead>
          <tr>
            <th>Select</th>
            <th>Username</th>
            <th>Email</th>
            <th>Contact No</th>
            <th>Address</th>
          </tr>
        </thead>
        <tbody>
          {vendors.map((vendor) => (
            <tr key={vendor.user_id}>
              <td>
                <input
                  type="checkbox"
                  value={vendor.username} // Store username in value
                  onChange={handleCheckboxChange}
                />
              </td>
              <td>{vendor.username}</td>
              <td>{vendor.email}</td>
              <td>{vendor.contactNo}</td>
              <td>{vendor.address}</td>
            </tr>
          ))}
        </tbody>

      </table>
      {selectedVendors.length > 0 &&
        <div>
          <p>Selected vendors:</p>
          <ul>
          {selectedVendors.map(vendorId => {
  const selectedVendor = vendors.find(vendor => vendor.user_id === vendorId);
  return selectedVendor ? (
    <li key={vendorId}>{selectedVendor.username}</li>
  ) : null;
})}
          </ul>
        </div>
      }
    </div>
  );
}

export default Vendors;

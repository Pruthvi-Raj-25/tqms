import React, { useState, useEffect } from "react";
import axios from "axios";
import { useLocation } from "react-router-dom";
import { useParams } from "react-router-dom";

// function Vendors() {
//   const [vendors, setVendors] = useState([]);
//   const [selectedVendors, setSelectedVendors] = useState([]);
//   const location = useLocation();

//   useEffect(() => {
//     const accessToken = new URLSearchParams(location.search).get("accessToken");
//     axios
//       .get(`http://127.0.0.1:5000/users?role=vendor`, {
//         headers: { Authorization: `Bearer ${accessToken}` },
//       })
//       .then((response) => {
//         if (response.data.success) {
//           setVendors(response.data.users);
//         } else {
//           console.log(response.data.message);
//         }
//       })
//       .catch((error) => {
//         console.log(error);
//       });
//   }, []);

//   const handleCheckboxChange = (event) => {
//     const vendorId = event.target.value;
//     if (event.target.checked) {
//       setSelectedVendors(prevSelected => [...prevSelected, vendorId]);
//     } else {
//       setSelectedVendors(prevSelected => prevSelected.filter(id => id !== vendorId));
//     }
//   };
  

//   const handleAssignClick = () => {
//     const tender_id = new URLSearchParams(location.search).get("tender_id");
//     const accessToken = new URLSearchParams(location.search).get("accessToken");
//     console.log("tender_id", tender_id);
//     axios
//       .post(
//         "http://127.0.0.1:5000/tenders/assign",
//         {
//           tender_id: tender_id,
//           vendor_ids: selectedVendors,
//         },
//         { headers: { Authorization: `Bearer ${accessToken}` } }
//       )
//       .then((response) => {
//         alert(response.data.message);
//         if (response.data.status === "success") {
//           console.log(response.data.message);
//           setSelectedVendors([]);
//         } else {
//           console.log(response.data.message);
//         }
//       })
//       .catch((error) => {
//         console.log(error);
//       });
//   };

//   const handlePopupClose = () => {
//     window.close(); // Close the current window
//   };

//   return (
//     <div>
//       <h1>Vendors</h1>
//       <button onClick={handleAssignClick}>Assign</button>
//       <button onClick={handlePopupClose}>Close</button>
//       <table border="2">
//         <thead>
//           <tr>
//             <th>Select</th>
//             <th>Username</th>
//             <th>Email</th>
//             <th>Contact No</th>
//             <th>Address</th>
//           </tr>
//         </thead>
//         <tbody>
//           {vendors.map((vendor) => (
//             <tr key={vendor._id}>
//               <td>
//                 <input type="checkbox" value={vendor._id} onChange={handleCheckboxChange} />
//               </td>
//               <td>{vendor.username}</td>
//               <td>{vendor.email}</td>
//               <td>{vendor.contactNo}</td>
//               <td>{vendor.address}</td>
//             </tr>
//           ))}
//         </tbody>
//       </table>
//       {selectedVendors.length > 0 && (
//         <div>
//           <p>Selected vendors:</p>
//           <ul>
//             {selectedVendors.map((vendorId) => {
//               const selectedVendor = vendors.find(
//                 (vendor) => vendor._id === vendorId
//               );
//               return selectedVendor ? (
//                 <li key={vendorId}>{selectedVendor.username}</li>
//               ) : null;
//             })}
//           </ul>
//         </div>
//       )}
//     </div>
//   );
// }



// function Vendors() {
//   const [vendors, setVendors] = useState([]);
//   const [selectedVendors, setSelectedVendors] = useState([]);
//   const location = useLocation();

//   useEffect(() => {
//     const accessToken = new URLSearchParams(location.search).get('accessToken');
//     axios.get(`http://127.0.0.1:5000/users?role=vendor`, { headers: { Authorization: `Bearer ${accessToken}` }})
//       .then(response => {
//         if (response.data.success) {
//           setVendors(response.data.users);
//         } else {
//           console.log(response.data.message);
//         }
//       })
//       .catch(error => {
//         console.log(error);
//       });
//   }, [location]);

//   const handleCheckboxChange = (event) => {
//     const vendorId = event.target.value;
//     if (event.target.checked) {
//       setSelectedVendors(prevSelected => [...prevSelected, vendorId]);
//     } else {
//       setSelectedVendors(prevSelected => prevSelected.filter(id => id !== vendorId));
//     }
//   };

//   const handleAssignClick = () => {
//     const tender_id = new URLSearchParams(location.search).get('tender_id');
//     const accessToken = new URLSearchParams(location.search).get('accessToken');
//     axios.post('http://127.0.0.1:5000/tenders/assign', {
//       tender_id: tender_id,
//       vendor_ids: selectedVendors
//     }, { headers: { Authorization: `Bearer ${accessToken}` }})
//       .then(response => {
//         alert(response.data.message);
//         if (response.data.status === 'success') {
//           setSelectedVendors([]);
//         } else {
//           console.log(response.data.message);
//         }
//       })
//       .catch(error => {
//         console.log(error);
//       });
//   };

//   const handlePopupClose = () => {
//     window.close(); // Close the current window
//   };

//   return (
//     <div>
//       <h1>Vendors</h1>
//       <button onClick={handleAssignClick}>Assign</button>
//       <button onClick={handlePopupClose}>Close</button>
//       <table border="2">
//         <thead>
//           <tr>
//             <th>Select</th>
//             <th>Username</th>
//             <th>Email</th>
//             <th>Contact No</th>
//             <th>Address</th>
//           </tr>
//         </thead>
//         <tbody>
//           {vendors.map(vendor => (
//             <tr key={vendor._id}>
//               <td><input type="checkbox" value={vendor._id} onChange={handleCheckboxChange} /></td>
//               <td>{vendor.username}</td>
//               <td>{vendor.email}</td>
//               <td>{vendor.contactNo}</td>
//               <td>{vendor.address}</td>
//             </tr>
//           ))}
//         </tbody>
//       </table>
//       {selectedVendors.length > 0 &&
//         <div>
//           <p>Selected vendors:</p>
//           <ul>
//             {selectedVendors.map(vendorId => {
//               const selectedVendor = vendors.find(vendor => vendor._id === vendorId);
//               return selectedVendor ? (
//                 <li key={vendorId}>{selectedVendor.username}</li>
//               ) : null;
//             })}
//           </ul>
//         </div>
//       }
//     </div>
//   );
// }

function Vendors() {
  const [vendors, setVendors] = useState([]);
  const [selectedVendors, setSelectedVendors] = useState([]);
  const location = useLocation();

  useEffect(() => {
    const accessToken = new URLSearchParams(location.search).get('accessToken');
    axios.get(`http://127.0.0.1:5000/users?role=vendor`, { headers: { Authorization: `Bearer ${accessToken}` }})
      .then(response => {
        if (response.data.success) {
          console.log('Vendors fetched:', response.data.users); // Log fetched vendors
          setVendors(response.data.users);
        } else {
          console.log(response.data.message);
        }
      })
      .catch(error => {
        console.log(error);
      });
  }, [location]);

  const handleCheckboxChange = (event) => {
    const vendorId = event.target.value;
    console.log('Selected vendor ID:', vendorId); // Log vendor ID
    if (event.target.checked) {
      setSelectedVendors(prevSelected => {
        const updated = [...prevSelected, vendorId];
        console.log('Updated selected vendors:', updated); // Log updated state
        return updated;
      });
    } else {
      setSelectedVendors(prevSelected => {
        const updated = prevSelected.filter(id => id !== vendorId);
        console.log('Updated selected vendors after removal:', updated); // Log after removal
        return updated;
      });
    }
  };

  const handleAssignClick = () => {
    const tender_id = new URLSearchParams(location.search).get('tender_id');
    const accessToken = new URLSearchParams(location.search).get('accessToken');
    axios.post('http://127.0.0.1:5000/tenders/assign', {
      tender_id: tender_id,
      vendor_ids: selectedVendors
    }, { headers: { Authorization: `Bearer ${accessToken}` }})
      .then(response => {
        alert(response.data.message);
        if (response.data.status === 'success') {
          setSelectedVendors([]);
        } else {
          console.log(response.data.message);
        }
      })
      .catch(error => {
        console.log(error);
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
          {vendors.map(vendor => (
            <tr key={vendor._id}>
              <td><input type="checkbox" value={vendor._id} onChange={handleCheckboxChange} /></td>
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
              const selectedVendor = vendors.find(vendor => vendor._id === vendorId);
              console.log('Selected vendor:', selectedVendor); // Log selected vendor object
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

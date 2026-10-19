const soap = require('soap');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { pool, testConnection } = require('./db');

// SOAP Service Implementation
const fishMarketService = {
  FishMarketPort: {
    FishMarketBinding: {
      GetFishPrice: async function (args) {
        const fishName = args.fishName;
        console.log(`📩 SOAP Request received for: ${fishName}`);

        try {
          const conn = await pool.getConnection();
          
          const [listings] = await conn.query(
            `SELECT 
              fc.name_bn AS fish_name_bn, fc.name_en AS fish_name_en,
              fl.price_per_kg, fl.quantity_kg, fl.created_at,
              l.division, l.district
             FROM fish_listings fl
             JOIN fish_categories fc ON fl.fish_category_id = fc.id
             LEFT JOIN locations l ON fl.location_id = l.id
             WHERE (fc.name_bn LIKE ? OR fc.name_en LIKE ?) AND fl.status = 'AVAILABLE'
             ORDER BY fl.created_at DESC
             LIMIT 1`,
            [`%${fishName}%`, `%${fishName}%`]
          );

          conn.release();

          if (listings.length > 0) {
            const listing = listings[0];
            const location = listing.district 
              ? `${listing.district}, ${listing.division}`
              : 'Bangladesh';

            return {
              fishName: listing.fish_name_bn,
              pricePerKg: parseFloat(listing.price_per_kg),
              availableQuantity: parseFloat(listing.quantity_kg),
              marketLocation: location,
              lastUpdated: new Date(listing.created_at).toLocaleString('bn-BD')
            };
          } else {
            return {
              fishName: fishName,
              pricePerKg: 0,
              availableQuantity: 0,
              marketLocation: 'No listing available',
              lastUpdated: new Date().toLocaleString('bn-BD')
            };
          }
        } catch (err) {
          console.error('SOAP DB error:', err);
          return {
            fishName: fishName,
            pricePerKg: 0,
            availableQuantity: 0,
            marketLocation: 'Database error',
            lastUpdated: new Date().toLocaleString('bn-BD')
          };
        }
      }
    }
  }
};

const PORT = 8000;

(async () => {
  try {
    await testConnection();
    
    const wsdlPath = path.join(__dirname, 'fishmarket.wsdl');
    const wsdlXml = fs.readFileSync(wsdlPath, 'utf8');

    const server = http.createServer();
    
    server.listen(PORT, () => {
      const soapServer = soap.listen(server, '/wsdl', fishMarketService, wsdlXml);
      console.log(`🐟 SOAP FishMarket Service running on http://localhost:${PORT}/wsdl?wsdl`);
      
      soapServer.log = function (type, data) {
        // Silent log
      };
    });
  } catch (err) {
    console.error('SOAP server error:', err);
    process.exit(1);
  }
})();

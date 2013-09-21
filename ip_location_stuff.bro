local g: geo_location = lookup_location(8.8.8.8);

print fmt("CC, %s", g$country_code);
print fmt("region, %s", g$region);
print fmt("city, %s", g$city);
print fmt("lat, %s", g$latitude);
print fmt("lon, %s", g$longitude);

local g2: count = lookup_asn(8.8.8.8);

print g2;


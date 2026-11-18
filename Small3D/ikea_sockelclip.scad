// IKEA Sockelclip (METOD Sockelhalterung) – Nachbau v3
// Maße per Bildauswertung aus den Fotos mit Meterstab (Draufsicht 22,9 px/mm,
// Seitenansicht 27,8 px/mm). Genauigkeit ca. ±0,5 mm – Beindurchmesser bitte nachmessen!
// Ausrichtung: Öffnung nach -X, Pfostenplatte mit Sockelhaken nach +X, Z = Höhe.
// Druck: flach auf dem Flansch, PETG.

$fn = 180;

/* [Klammer] */
innen_d     = 33.0;  // Innendurchmesser = Beindurchmesser (Foto: 33,0 mm)
oeffnung_w  = 92;    // Öffnungswinkel (Foto: ca. 92°)
breite_hint = 6.5;   // Breite des Rings hinten (am Pfosten)
breite_spit = 3.3;   // Breite an den Spitzen -> dünner, damit die Enden federn
flansch_t   = 1.6;   // Flanschdicke
wand_b      = 2.0;   // hochstehende Innenwand: Breite
wand_h      = 6.3;   // hochstehende Innenwand: Höhe (Foto: 6,3 mm)

/* [Ohren an den Spitzen] */
ohr_r  = 23.9;       // Radius bis Ohrspitze
ohr_b  = 2.6;        // Breite
ohr_w  = 30;         // Neigung Richtung Öffnung (Grad)

/* [Pfostenplatte] */
platte_x     = 21.5; // Außenfläche Platte vom Mittelpunkt
platte_t     = 1.5;  // Plattendicke
platte_h     = 15.1; // Gesamthöhe (Foto: 15,1 mm)
breite_unten = 25;
breite_oben  = 11;
schraeg_von  = 3;
schraeg_bis  = 9;

/* [Untere Lippe] */
ul_z      = 1.8;   // Unterkante
ul_t      = 1.4;   // Dicke des Arms
ul_l      = 3.2;   // Auskragung ab Platte
ul_spitze = 5.2;   // Oberkante der nach oben zeigenden Spitze
ul_st     = 1.3;   // Dicke der Spitze
ul_b      = 24;    // Breite

/* [Oberer U-Haken] */
oh_t     = 1.6;    // Dicke Deckplatte
oh_kanal = 1.8;    // Kanalbreite
oh_lt    = 1.5;    // Lippendicke
oh_unten = 10.8;   // Unterkante der Lippe

ri = innen_d/2;
ph = oeffnung_w/2;              // halbe Öffnung, gemessen von -X
// Außenkontur: exzentrischer Kreis -> hinten breit, an den Spitzen schmal
// r(phi) = R + d*cos(phi), phi von +X
_d = (breite_hint - breite_spit) / (1 + cos(ph));
_R = ri + breite_hint - _d;
px = platte_x - platte_t;

module c_ausschnitt()   // Keil der Öffnung
    polygon([[0,0], [-60, 60*tan(ph)], [-60, -60*tan(ph)]]);

module ring2d()
    difference() {
        intersection() {
            translate([_d, 0]) circle(r = _R);
            translate([-60, -60]) square([60 + platte_x, 120]);
        }
        circle(r = ri);
        c_ausschnitt();
    }

// abgerundete Spitzen
module spitzen2d()
    for (s = [-1, 1]) {
        a = 180 - s*ph;
        rm = ri + (breite_spit)/2;
        translate([rm*cos(a), rm*sin(a)]) circle(d = breite_spit);
    }

module klammer() {
    linear_extrude(flansch_t) union() { ring2d(); spitzen2d(); }
    linear_extrude(wand_h) difference() {
        circle(r = ri + wand_b);
        circle(r = ri);
        c_ausschnitt();
    }
    // runde Enden der Wand
    for (s = [-1, 1]) {
        a = 180 - s*ph;
        translate([(ri + wand_b/2)*cos(a), (ri + wand_b/2)*sin(a), 0])
            cylinder(d = wand_b, h = wand_h);
    }
}

module ohren()
    for (s = [-1, 1]) {
        a = 180 - s*ph;
        rm = ri + breite_spit/2;
        translate([rm*cos(a), rm*sin(a), 0])
            rotate([0, 0, a - s*ohr_w])
                translate([0, -ohr_b/2, 0]) cube([ohr_r - rm, ohr_b, flansch_t]);
    }

module pfostenplatte()
    translate([px, 0, 0]) rotate([90, 0, 90]) linear_extrude(platte_t)
        polygon([[-breite_unten/2, 0], [breite_unten/2, 0],
                 [breite_unten/2, schraeg_von], [breite_oben/2, schraeg_bis],
                 [breite_oben/2, platte_h], [-breite_oben/2, platte_h],
                 [-breite_oben/2, schraeg_bis], [-breite_unten/2, schraeg_von]]);

module verbindung()   // Steg zwischen Innenwand und Platte
    difference() {
        translate([ri, -breite_oben/2, 0]) cube([px - ri + 0.1, breite_oben, wand_h]);
        translate([0, 0, -1]) cylinder(r = ri, h = wand_h + 2);
    }

module untere_lippe() {
    translate([platte_x - 0.1, -ul_b/2, ul_z]) cube([ul_l + 0.1, ul_b, ul_t]);
    translate([platte_x + ul_l - ul_st, -ul_b/2, ul_z]) cube([ul_st, ul_b, ul_spitze - ul_z]);
}

module u_haken() {
    translate([platte_x - 0.1, -breite_oben/2, platte_h - oh_t])
        cube([oh_kanal + oh_lt + 0.1, breite_oben, oh_t]);
    translate([platte_x + oh_kanal, -breite_oben/2, oh_unten])
        cube([oh_lt, breite_oben, platte_h - oh_unten]);
}

union() {
    klammer();
    ohren();
    pfostenplatte();
    verbindung();
    untere_lippe();
    u_haken();
}

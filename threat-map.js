// Threat Map — D3.js + TopoJSON interactive cyber threat world map
// Renders an SVG world map with threat actors, attack arcs, IXPs, and cables
// Inspired by qeeqbox/raven threat map approach

(function() {
  'use strict';

  var _tmWorldData = null;
  var _tmLoading = false;
  var _tmD3Ready = false;
  var _tmTopoReady = false;
  var _tmInstances = {};

  var HOSTILE_COUNTRIES = {
    643: '#2a0a0a', // Russia
    156: '#2a0a0a', // China
    408: '#2a0a0a', // North Korea
    364: '#2a0a0a', // Iran
    // 2nd tier hostile
    112: '#1a0808', // Belarus
    760: '#1a0808'  // Syria
  };

  var ALLIED_COUNTRIES = {
    840: '#0a0a2a', // United States
    826: '#0a0a2a', // United Kingdom
    376: '#0a0a2a', // Israel
    36:  '#0a0a2a', // Australia
    124: '#0a0a2a', // Canada
    554: '#0a0a2a', // New Zealand
    // NATO / Five Eyes adjacent
    276: '#080820', // Germany
    250: '#080820', // France
    528: '#080820', // Netherlands
    380: '#080820', // Italy
    724: '#080820', // Spain
    616: '#080820', // Poland
    392: '#080820', // Japan
    410: '#080820', // South Korea
    158: '#080820', // Taiwan
    233: '#080820', // Estonia
    428: '#080820', // Latvia
    440: '#080820'  // Lithuania
  };

  var CONFLICT_COUNTRIES = {
    804: '#2a1a0a' // Ukraine
  };

  var COUNTRY_NAMES = {
    643: 'Russia', 156: 'China', 408: 'North Korea', 364: 'Iran',
    840: 'United States', 826: 'United Kingdom', 376: 'Israel',
    36: 'Australia', 124: 'Canada', 554: 'New Zealand',
    276: 'Germany', 250: 'France', 528: 'Netherlands', 804: 'Ukraine',
    380: 'Italy', 724: 'Spain', 616: 'Poland', 392: 'Japan',
    410: 'South Korea', 158: 'Taiwan', 356: 'India', 586: 'Pakistan',
    792: 'Turkey', 704: 'Vietnam', 702: 'Singapore', 76: 'Brazil',
    233: 'Estonia', 112: 'Belarus', 760: 'Syria'
  };

  var COUNTRY_THREAT_INFO = {
    643: { level: 'CRITICAL', apts: 'APT28, APT29, Sandworm, Turla, Gamaredon', incidents: 'SolarWinds, NotPetya, Ukraine grid attacks' },
    156: { level: 'CRITICAL', apts: 'APT41, Volt Typhoon, Salt Typhoon, APT1, Hafnium', incidents: 'OPM breach, Volt Typhoon pre-positioning, Salt Typhoon telecom' },
    408: { level: 'HIGH', apts: 'Lazarus, Kimsuky, Andariel, BlueNoroff', incidents: 'WannaCry, Sony Pictures, $3B+ crypto theft' },
    364: { level: 'HIGH', apts: 'APT33, APT34, APT35, MuddyWater', incidents: 'Shamoon, Albania attack, Israeli water systems' },
    840: { level: 'ALLIED', apts: 'NSA TAO, Equation Group', incidents: 'Stuxnet, Olympic Games' },
    826: { level: 'ALLIED', apts: 'GCHQ/JTRIG', incidents: 'Counter-ISIS, Five Eyes ops' },
    376: { level: 'ALLIED', apts: 'Unit 8200', incidents: 'Stuxnet, Duqu, Flame' },
    804: { level: 'CONFLICT ZONE', apts: 'Target of Russian cyber ops', incidents: 'Ongoing grid/comms attacks since 2022' }
  };

  function _esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function(c) {
      return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
    });
  }

  function _loadScript(url, checkFn, cb) {
    if (checkFn()) { cb(); return; }
    var s = document.createElement('script');
    s.src = url;
    s.onload = function() { cb(); };
    s.onerror = function() { cb(new Error('Failed to load ' + url)); };
    document.head.appendChild(s);
  }

  function _ensureLibs(cb) {
    var pending = 2;
    function done() { if (--pending === 0) cb(); }

    _loadScript(
      '/js/vendor/d3.min.js',
      function() { return typeof d3 !== 'undefined'; },
      function(err) { if (!err) _tmD3Ready = true; done(); }
    );

    _loadScript(
      '/js/vendor/topojson-client.min.js',
      function() { return typeof topojson !== 'undefined'; },
      function(err) { if (!err) _tmTopoReady = true; done(); }
    );
  }

  function _loadWorldData(cb) {
    if (_tmWorldData) { cb(_tmWorldData); return; }
    if (_tmLoading) {
      var check = setInterval(function() {
        if (_tmWorldData) { clearInterval(check); cb(_tmWorldData); }
      }, 100);
      return;
    }
    _tmLoading = true;
    fetch('/js/vendor/countries-110m.json')
      .then(function(r) { return r.json(); })
      .then(function(world) {
        _tmWorldData = world;
        _tmLoading = false;
        cb(world);
      })
      .catch(function() {
        _tmLoading = false;
        cb(null);
      });
  }

  function _getCountryFill(id) {
    var numId = +id;
    if (HOSTILE_COUNTRIES[numId]) return HOSTILE_COUNTRIES[numId];
    if (ALLIED_COUNTRIES[numId]) return ALLIED_COUNTRIES[numId];
    if (CONFLICT_COUNTRIES[numId]) return CONFLICT_COUNTRIES[numId];
    return '#101820';
  }

  function _buildThreatMap(containerId, opts) {
    var container = document.getElementById(containerId);
    if (!container) return;

    var actors = opts.actors || [];
    var arcs = opts.arcs || [];
    var ixps = opts.ixps || [];
    var cables = opts.cables || [];

    var rect = container.getBoundingClientRect();
    var width = opts.width || rect.width || 800;
    var height = opts.height || rect.height || 420;

    if (_tmInstances[containerId]) {
      try { _tmInstances[containerId].cleanup(); } catch(e) {}
    }

    container.innerHTML = '';
    container.style.position = 'relative';
    container.style.overflow = 'hidden';
    container.style.background = '#0a0e14';

    var svg = d3.select('#' + containerId)
      .append('svg')
      .attr('width', width)
      .attr('height', height)
      .style('background', '#0a0e14')
      .style('display', 'block');

    var defs = svg.append('defs');

    // Glow filter for threat dots
    var glowFilter = defs.append('filter').attr('id', 'tm-glow');
    glowFilter.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'blur');
    var merge = glowFilter.append('feMerge');
    merge.append('feMergeNode').attr('in', 'blur');
    merge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Arc glow
    var arcGlow = defs.append('filter').attr('id', 'tm-arc-glow');
    arcGlow.append('feGaussianBlur').attr('stdDeviation', '2').attr('result', 'blur');
    var arcMerge = arcGlow.append('feMerge');
    arcMerge.append('feMergeNode').attr('in', 'blur');
    arcMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    var g = svg.append('g');

    // Projection
    var projection = d3.geoNaturalEarth1()
      .scale(width / 5.8)
      .translate([width / 2, height / 2]);

    var path = d3.geoPath().projection(projection);

    // Zoom
    var zoom = d3.zoom()
      .scaleExtent([1, 12])
      .on('zoom', function(event) {
        g.attr('transform', event.transform);
      });

    svg.call(zoom);

    // Tooltip
    var tooltip = d3.select('#' + containerId)
      .append('div')
      .style('position', 'absolute')
      .style('background', 'rgba(8,12,20,0.95)')
      .style('border', '1px solid #1a4a6a')
      .style('border-radius', '4px')
      .style('padding', '10px 14px')
      .style('font-family', '"Courier New", monospace')
      .style('font-size', '10px')
      .style('color', '#8ab4d4')
      .style('pointer-events', 'none')
      .style('z-index', '100')
      .style('max-width', '280px')
      .style('box-shadow', '0 4px 20px rgba(0,0,0,0.6)')
      .style('display', 'none');

    // Actor detail popup
    var popup = d3.select('#' + containerId)
      .append('div')
      .attr('id', 'tm-popup')
      .style('position', 'absolute')
      .style('background', 'rgba(8,12,20,0.96)')
      .style('border', '1px solid #1a4a6a')
      .style('border-radius', '6px')
      .style('padding', '14px 18px')
      .style('font-family', '"Courier New", monospace')
      .style('font-size', '11px')
      .style('color', '#8ab4d4')
      .style('pointer-events', 'auto')
      .style('z-index', '200')
      .style('max-width', '360px')
      .style('box-shadow', '0 4px 24px rgba(0,0,0,0.7)')
      .style('display', 'none');

    // Render world
    var countries = topojson.feature(_tmWorldData, _tmWorldData.objects.countries);

    // Ocean
    g.append('rect')
      .attr('width', width * 4)
      .attr('height', height * 4)
      .attr('x', -width * 1.5)
      .attr('y', -height * 1.5)
      .attr('fill', '#060a10');

    // Graticule
    var graticule = d3.geoGraticule();
    g.append('path')
      .datum(graticule())
      .attr('d', path)
      .attr('fill', 'none')
      .attr('stroke', '#0d1a28')
      .attr('stroke-width', 0.3);

    // Countries
    g.selectAll('.tm-country')
      .data(countries.features)
      .enter()
      .append('path')
      .attr('class', 'tm-country')
      .attr('d', path)
      .attr('fill', function(d) { return _getCountryFill(d.id); })
      .attr('stroke', '#0a2a44')
      .attr('stroke-width', 0.5)
      .style('cursor', 'pointer')
      .on('mouseover', function(event, d) {
        d3.select(this).attr('stroke', '#00aaff').attr('stroke-width', 1.2);
        var numId = +d.id;
        var name = COUNTRY_NAMES[numId] || ('Country ' + d.id);
        var info = COUNTRY_THREAT_INFO[numId];
        var html = '<div style="color:#00ddff;font-weight:bold;font-size:12px;margin-bottom:4px;letter-spacing:1px;">' + _esc(name) + '</div>';
        if (info) {
          var lvlColor = info.level === 'CRITICAL' ? '#ff2244' : info.level === 'HIGH' ? '#ff6622' : info.level === 'CONFLICT ZONE' ? '#ffaa00' : '#44aaff';
          html += '<div style="margin:2px 0;"><span style="color:#4a7a9a;">THREAT:</span> <span style="color:' + lvlColor + ';font-weight:bold;">' + _esc(info.level) + '</span></div>';
          html += '<div style="margin:2px 0;"><span style="color:#4a7a9a;">APT GROUPS:</span> <span style="color:#bbb;font-size:9px;">' + _esc(info.apts) + '</span></div>';
          html += '<div style="margin:2px 0;"><span style="color:#4a7a9a;">RECENT:</span> <span style="color:#bbb;font-size:9px;">' + _esc(info.incidents) + '</span></div>';
        } else {
          html += '<div style="color:#4a6a8a;">No active threat intelligence</div>';
        }
        tooltip.html(html).style('display', 'block');
        var pos = d3.pointer(event, container);
        tooltip.style('left', Math.min(pos[0] + 12, width - 290) + 'px')
               .style('top', Math.max(pos[1] - 60, 4) + 'px');
      })
      .on('mousemove', function(event) {
        var pos = d3.pointer(event, container);
        tooltip.style('left', Math.min(pos[0] + 12, width - 290) + 'px')
               .style('top', Math.max(pos[1] - 60, 4) + 'px');
      })
      .on('mouseout', function() {
        d3.select(this).attr('stroke', '#0a2a44').attr('stroke-width', 0.5);
        tooltip.style('display', 'none');
      });

    // Borders
    g.append('path')
      .datum(topojson.mesh(_tmWorldData, _tmWorldData.objects.countries, function(a, b) { return a !== b; }))
      .attr('d', path)
      .attr('fill', 'none')
      .attr('stroke', '#0a2a44')
      .attr('stroke-width', 0.4);

    // --- UNDERSEA CABLES ---
    if (cables.length > 0) {
      var cableGroup = g.append('g').attr('class', 'tm-cables');
      cables.forEach(function(cable) {
        var coords = [[cable.from.lon, cable.from.lat], [cable.to.lon, cable.to.lat]];
        var lineGen = d3.geoPath().projection(projection);
        var geojson = { type: 'Feature', geometry: { type: 'LineString', coordinates: coords } };
        cableGroup.append('path')
          .datum(geojson)
          .attr('d', lineGen)
          .attr('fill', 'none')
          .attr('stroke', '#0d3a2a')
          .attr('stroke-width', 0.8)
          .attr('stroke-dasharray', '4,3')
          .attr('opacity', 0.5);
      });
    }

    // --- IXP DOTS ---
    if (ixps.length > 0) {
      var ixpGroup = g.append('g').attr('class', 'tm-ixps');
      ixps.forEach(function(ixp) {
        var pt = projection([ixp.lon, ixp.lat]);
        if (!pt) return;
        ixpGroup.append('circle')
          .attr('cx', pt[0])
          .attr('cy', pt[1])
          .attr('r', 3)
          .attr('fill', '#00ff88')
          .attr('opacity', 0.6)
          .attr('filter', 'url(#tm-glow)');
      });
    }

    // --- ATTACK ARCS ---
    var arcGroup = g.append('g').attr('class', 'tm-arcs');
    var arcPaths = [];
    arcs.forEach(function(arc) {
      var fromActor = null;
      for (var a = 0; a < actors.length; a++) {
        if (actors[a].id === arc.from) { fromActor = actors[a]; break; }
      }
      if (!fromActor) return;

      var coords = [[fromActor.lon, fromActor.lat], [arc.toLon, arc.toLat]];
      var geojson = { type: 'Feature', geometry: { type: 'LineString', coordinates: coords } };
      var lineGen = d3.geoPath().projection(projection);

      var arcPath = arcGroup.append('path')
        .datum(geojson)
        .attr('d', lineGen)
        .attr('fill', 'none')
        .attr('stroke', arc.color || '#ff3333')
        .attr('stroke-width', 1.2)
        .attr('stroke-dasharray', '6,4')
        .attr('opacity', 0.5)
        .attr('filter', 'url(#tm-arc-glow)');

      arcPaths.push(arcPath);
    });

    // --- THREAT ACTOR DOTS ---
    var dotGroup = g.append('g').attr('class', 'tm-actors');
    var pulseDots = [];

    actors.forEach(function(actor) {
      var pt = projection([actor.lon, actor.lat]);
      if (!pt) return;

      var isHostile = actor.alignment === 'hostile';
      var color = isHostile ? '#ff3333' : '#4488ff';
      var radius = actor.tier === 'TIER-1' ? 6 : 4;

      // Outer pulse ring
      var pulse = dotGroup.append('circle')
        .attr('cx', pt[0])
        .attr('cy', pt[1])
        .attr('r', radius)
        .attr('fill', 'none')
        .attr('stroke', color)
        .attr('stroke-width', 1)
        .attr('opacity', 0.6);

      pulseDots.push({ el: pulse, baseR: radius, color: color });

      // Core dot
      dotGroup.append('circle')
        .attr('cx', pt[0])
        .attr('cy', pt[1])
        .attr('r', radius * 0.6)
        .attr('fill', color)
        .attr('filter', 'url(#tm-glow)')
        .style('cursor', 'pointer')
        .on('click', function(event) {
          event.stopPropagation();
          var alignClass = isHostile ? 'color:#ff4444' : 'color:#44aaff';
          var tierColor = actor.tier === 'TIER-1' ? 'background:rgba(255,34,34,0.12);color:#ff4444;border:1px solid #ff2222' : 'background:rgba(255,136,0,0.12);color:#ffaa44;border:1px solid #ff8800';
          var h = '<div style="position:absolute;top:6px;right:10px;color:#4a6a8a;cursor:pointer;font-size:16px;" onclick="document.getElementById(\'tm-popup\').style.display=\'none\'">x</div>';
          h += '<div style="' + alignClass + ';font-weight:bold;font-size:13px;letter-spacing:1px;margin-bottom:6px;padding-right:20px;">' + _esc(actor.name) + '</div>';
          h += '<div style="margin:3px 0;"><span style="color:#4a7a9a;">NATION:</span> ' + _esc(actor.nation) + '</div>';
          h += '<div style="margin:3px 0;"><span style="color:#4a7a9a;">TIER:</span> <span style="display:inline-block;padding:1px 6px;border-radius:2px;font-size:10px;letter-spacing:1px;' + tierColor + ';">' + _esc(actor.tier) + '</span></div>';
          h += '<div style="margin:3px 0;"><span style="color:#4a7a9a;">DESIGNATION:</span> <span style="' + alignClass + ';font-weight:bold;">' + (isHostile ? 'HOSTILE' : 'ALLIED') + '</span></div>';
          h += '<div style="margin:3px 0;"><span style="color:#4a7a9a;">CITY:</span> ' + _esc(actor.city) + '</div>';
          h += '<div style="margin:3px 0;"><span style="color:#4a7a9a;">APT GROUPS:</span> <span style="font-size:9px;color:#bbb;">' + _esc(actor.aptGroups) + '</span></div>';
          h += '<div style="margin:3px 0;"><span style="color:#4a7a9a;">RECENT OPS:</span> <span style="font-size:9px;color:#bbb;">' + _esc(actor.recentOps) + '</span></div>';
          h += '<div style="margin:3px 0;"><span style="color:#4a7a9a;">CAPABILITIES:</span> <span style="font-size:9px;color:#bbb;">' + _esc(actor.capabilities) + '</span></div>';
          h += '<div style="margin-top:6px;border-top:1px solid #1a3a5a;padding-top:4px;"><span style="color:#4a7a9a;">SIGINT NOTE:</span> <span style="font-size:9px;color:#6a8aaa;">' + _esc(actor.notes) + '</span></div>';

          popup.html(h).style('display', 'block');
          var pos = d3.pointer(event, container);
          popup.style('left', Math.min(pos[0] + 10, width - 380) + 'px')
               .style('top', Math.max(pos[1] - 100, 4) + 'px');
        });

      // Label
      if (actor.tier === 'TIER-1') {
        dotGroup.append('text')
          .attr('x', pt[0])
          .attr('y', pt[1] - radius - 4)
          .attr('text-anchor', 'middle')
          .attr('fill', color)
          .attr('font-family', '"Courier New", monospace')
          .attr('font-size', '8px')
          .attr('opacity', 0.7)
          .text(actor.id.toUpperCase());
      }
    });

    // Close popup on background click
    svg.on('click', function() {
      popup.style('display', 'none');
    });

    // --- ANIMATIONS ---
    var animRunning = true;
    var startTime = Date.now();

    function animate() {
      if (!animRunning) return;
      var elapsed = (Date.now() - startTime) / 1000;

      // Pulse threat dots
      for (var i = 0; i < pulseDots.length; i++) {
        var pd = pulseDots[i];
        var phase = (elapsed * 0.8 + i * 0.3) % 1;
        var r = pd.baseR + pd.baseR * 1.5 * phase;
        var alpha = 0.6 * (1 - phase);
        pd.el.attr('r', r).attr('opacity', alpha);
      }

      // Animate arc dashes
      for (var j = 0; j < arcPaths.length; j++) {
        var offset = (elapsed * 15 + j * 5) % 20;
        arcPaths[j].attr('stroke-dashoffset', -offset);
        var arcAlpha = 0.3 + 0.3 * Math.abs(Math.sin(elapsed * 0.5 + j * 0.4));
        arcPaths[j].attr('opacity', arcAlpha);
      }

      requestAnimationFrame(animate);
    }
    animate();

    // Cleanup function
    _tmInstances[containerId] = {
      cleanup: function() {
        animRunning = false;
        container.innerHTML = '';
      }
    };

    // Resize handler
    var resizeTimer = null;
    var resizeHandler = function() {
      if (resizeTimer) clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function() {
        var newRect = container.getBoundingClientRect();
        if (newRect.width > 0 && newRect.width !== width) {
          _buildThreatMap(containerId, opts);
        }
      }, 300);
    };
    window.addEventListener('resize', resizeHandler);
  }

  // --- PUBLIC API ---
  window.renderThreatMap = function(containerId, opts) {
    opts = opts || {};
    var container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;font-family:monospace;color:#00aaff;font-size:12px;letter-spacing:2px;">LOADING THREAT MAP...</div>';

    _ensureLibs(function() {
      if (!_tmD3Ready || !_tmTopoReady) {
        container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;font-family:monospace;color:#ff4444;font-size:11px;">Failed to load D3.js or TopoJSON from CDN</div>';
        return;
      }
      _loadWorldData(function(world) {
        if (!world) {
          container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;font-family:monospace;color:#ff4444;font-size:11px;">Failed to load world map data</div>';
          return;
        }
        _buildThreatMap(containerId, opts);
      });
    });
  };

  window.destroyThreatMap = function(containerId) {
    if (_tmInstances[containerId]) {
      _tmInstances[containerId].cleanup();
      delete _tmInstances[containerId];
    }
  };
})();

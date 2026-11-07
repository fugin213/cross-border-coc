// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Cross-border Chain of Custody with SPOC-mediated sharing and RBAC
/// @notice Implements case creation, evidence addition, domestic and cross-border transfer,
///         case queries, evidence verification, custody acknowledgment and recovery,
///         personnel management, and append-only correction and dispute records.
///         Storage layout: history actions are stored as enum codes; countries as
///         ISO 3166-1 alpha-2 codes (bytes2); small struct fields share 32-byte slots;
///         per-evidence permitted countries are kept in a mapping and reconstructed in views.
contract CrossBorderCoCOpt {
    // ---------------------------------------------------------------------
    // Types
    // ---------------------------------------------------------------------
    enum Role {
        None,
        LawEnforcementOfficer,
        FirstResponder,
        SPOC
    }

    enum Action {
        CaseCreated,          // 0
        EvidenceAdded,        // 1
        DomesticTransfer,     // 2
        CrossborderTransfer,  // 3
        CustodyAcknowledged,  // 4
        EvidenceVerified,     // 5
        VerificationFailed,   // 6
        CustodyRecovered,     // 7
        CorrectionRecorded,   // 8
        DisputeRecorded       // 9
    }

    enum CorrectionKind {
        Correction, // 0: the jurisdiction that made the entry corrects it
        Dispute     // 1: any participating jurisdiction contests it
    }

    enum TargetType {
        HistoryEntry, // 0: targetIndex is a 0-based index into the case history
        Evidence      // 1: targetIndex is an evidence id (1-based)
    }

    /// @dev Append-only correction or dispute; the original entry is never modified.
    struct Correction {
        CorrectionKind kind;   // \
        TargetType targetType; //  |
        bytes2 country;        //  > slot 0 (1 + 1 + 2 + 8 + 20 bytes)
        uint64 time;           //  |
        address author;        // /
        uint256 targetIndex;
        string note; // reason or a reference to an off-chain decision; no personal data
    }

    struct Officer {
        Role role;       // \
        bool active;     //  > slot 0 (1 + 1 + 2 bytes)
        bytes2 country;  // /
        string name;
        string organization;
    }

    struct EvidenceInput {
        string name;
        string evidenceType;
        bytes32 hash;          // computed off-chain over the forensic acquisition
        string hashAlgorithm;  // e.g. "SHA-256"
        string storagePointer; // off-chain location (repository URI, IPFS CID, ...)
    }

    struct Evidence {
        uint32 id;           // \
        uint64 createdTime;  //  > slot 0 (4 + 8 + 20 bytes)
        address createdBy;   // /
        bytes32 hash;
        string name;
        string evidenceType;
        string hashAlgorithm;
        string storagePointer;
    }

    /// @dev Return type for evidence; permittedCountries is reconstructed from the mapping.
    struct EvidenceView {
        uint256 id;
        string name;
        address createdBy;
        uint64 createdTime;
        string evidenceType;
        bytes32 hash;
        string hashAlgorithm;
        string storagePointer;
        bytes2[] permittedCountries;
    }

    struct HistoryEntry {
        Action action;       // \
        uint64 time;         //  > slot 0 (1 + 8 + 20 bytes)
        address from;        // /
        address to;          // \
        bytes2 fromCountry;  //  > slot 1 (20 + 2 + 2 bytes)
        bytes2 toCountry;    // /
    }

    struct Case {
        uint32 id;            // \
        uint64 ctime;         //  > slot 0 (4 + 8 + 20 bytes)
        address globalOwner;  // /
        bytes2[] countryIncharge; // 16 countries per slot
        mapping(bytes2 => bool) isCountryIncharge;
        mapping(bytes2 => address) localOwners;
        Evidence[] evs;
        mapping(uint256 => mapping(bytes2 => bool)) isPermitted; // evidenceId => country => permitted
        HistoryEntry[] history;
        Correction[] corrections;
    }

    struct CaseView {
        address globalOwner;
        uint64 ctime;
        bytes2[] countries;
        address[] localOwners;
        EvidenceView[] evidence; // only items permitted for the caller's country
        HistoryEntry[] history;
    }

    // ---------------------------------------------------------------------
    // State
    // ---------------------------------------------------------------------
    address public immutable admin;
    uint256 public caseCount;
    mapping(address => Officer) public officers;
    mapping(address => mapping(uint256 => bool)) public caseIncharge;
    mapping(uint256 => Case) private cases;

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------
    event OfficerAdded(address indexed account, Role role, bytes2 country, address indexed by);
    event OfficerRevoked(address indexed account, address indexed by);
    event EvidenceAdded(uint256 indexed caseId, uint256 indexed evidenceId, bytes32 hash, address indexed by);
    event CustodyEvent(
        uint256 indexed caseId,
        Action action,
        address indexed from,
        address indexed to,
        bytes2 fromCountry,
        bytes2 toCountry
    );
    event EvidenceVerified(uint256 indexed caseId, uint256 indexed evidenceId, address indexed verifier, bool ok);
    event CorrectionRecorded(
        uint256 indexed caseId,
        CorrectionKind kind,
        TargetType targetType,
        uint256 targetIndex,
        address indexed author
    );

    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------
    error OwnerStillActive();
    error InvalidTarget();
    error NotEntryJurisdiction();
    error NotAdmin();
    error NotActiveOfficer();
    error WrongRole();
    error InvalidRole();
    error AlreadyRegistered();
    error CountryMismatch();
    error SameCountry();
    error CaseNotFound();
    error CountryNotInCharge();
    error NotAssigned();
    error NotOwner();
    error EmptyEvidence();
    error EvidenceNotFound();
    error EvidenceNotPermitted();

    constructor() {
        admin = msg.sender;
    }

    // =====================================================================
    // Personnel management
    // =====================================================================
    function registerSPOC(address account, bytes2 country, string calldata name, string calldata organization)
        external
    {
        if (msg.sender != admin) revert NotAdmin();
        if (officers[account].role != Role.None) revert AlreadyRegistered();
        officers[account] = Officer(Role.SPOC, true, country, name, organization);
        emit OfficerAdded(account, Role.SPOC, country, msg.sender);
    }

    function addOfficer(address account, Role role, string calldata name, string calldata organization) external {
        Officer storage s = _activeOfficer(msg.sender);
        if (s.role != Role.SPOC) revert WrongRole();
        if (role == Role.None) revert InvalidRole();
        if (officers[account].role != Role.None) revert AlreadyRegistered();
        officers[account] = Officer(role, true, s.country, name, organization);
        emit OfficerAdded(account, role, s.country, msg.sender);
    }

    function revokeOfficer(address account) external {
        Officer storage s = _activeOfficer(msg.sender);
        if (s.role != Role.SPOC) revert WrongRole();
        Officer storage o = officers[account];
        if (!o.active) revert NotActiveOfficer();
        if (o.country != s.country) revert CountryMismatch();
        o.active = false;
        emit OfficerRevoked(account, msg.sender);
    }

    // =====================================================================
    // Algorithm 1: caseCreation
    // =====================================================================
    function caseCreation(EvidenceInput[] calldata items) external returns (uint256 caseId) {
        Officer storage u = _activeOfficer(msg.sender);
        if (u.role != Role.FirstResponder) revert WrongRole();
        if (items.length == 0) revert EmptyEvidence();

        caseId = ++caseCount;
        Case storage c = cases[caseId];
        c.id = uint32(caseId);
        c.ctime = uint64(block.timestamp);
        c.globalOwner = msg.sender;
        c.countryIncharge.push(u.country);
        c.isCountryIncharge[u.country] = true;
        c.localOwners[u.country] = msg.sender;
        caseIncharge[msg.sender][caseId] = true;

        _addEvidence(c, items, u.country);
        _log(c, Action.CaseCreated, msg.sender, address(0), u.country, u.country);
    }

    // =====================================================================
    // Algorithm 2: evidenceAddition
    // =====================================================================
    function evidenceAddition(uint256 caseId, EvidenceInput[] calldata items) external {
        Officer storage u = _activeOfficer(msg.sender);
        if (u.role != Role.FirstResponder) revert WrongRole();
        if (items.length == 0) revert EmptyEvidence();
        Case storage c = _getCase(caseId);
        _checkAccess(c, msg.sender, u.country);
        if (!_isOwner(c, msg.sender, u.country)) revert NotOwner();

        _addEvidence(c, items, u.country);
        _log(c, Action.EvidenceAdded, msg.sender, address(0), u.country, u.country);
    }

    // =====================================================================
    // Algorithm 3: domesticTransfer
    // =====================================================================
    function domesticTransfer(uint256 caseId, address to) external {
        Officer storage s = _activeOfficer(msg.sender);
        Officer storage r = _activeOfficer(to);
        if (s.country != r.country) revert CountryMismatch();
        Case storage c = _getCase(caseId);
        _checkAccess(c, msg.sender, s.country);
        if (!_isOwner(c, msg.sender, s.country)) revert NotOwner();

        if (c.globalOwner == msg.sender) {
            c.globalOwner = to;
        }
        c.localOwners[s.country] = to;
        caseIncharge[to][caseId] = true;

        _log(c, Action.DomesticTransfer, msg.sender, to, s.country, r.country);
    }

    // =====================================================================
    // Algorithm 4: crossborderTransfer
    // =====================================================================
    function crossborderTransfer(uint256 caseId, address to, uint256[] calldata sharedEvidenceIds) external {
        Officer storage s = _activeOfficer(msg.sender);
        Officer storage r = _activeOfficer(to);
        if (s.role != Role.SPOC || r.role != Role.SPOC) revert WrongRole();
        if (s.country == r.country) revert SameCountry();
        Case storage c = _getCase(caseId);
        if (c.globalOwner != msg.sender) revert NotOwner();

        // A country joining the case gets the receiving SPOC as its local owner. When more
        // evidence is later shared with a country already in charge, its local owner is kept,
        // so the originating country cannot reassign custody inside another jurisdiction.
        if (!c.isCountryIncharge[r.country]) {
            c.countryIncharge.push(r.country);
            c.isCountryIncharge[r.country] = true;
            c.localOwners[r.country] = to;
        }
        caseIncharge[to][caseId] = true;

        uint256 total = c.evs.length;
        for (uint256 i = 0; i < sharedEvidenceIds.length; i++) {
            uint256 id = sharedEvidenceIds[i];
            if (id == 0 || id > total) revert EvidenceNotFound();
            // The sending country can only share evidence it is itself permitted to access.
            if (!c.isPermitted[id][s.country]) revert EvidenceNotPermitted();
            c.isPermitted[id][r.country] = true;
        }

        _log(c, Action.CrossborderTransfer, msg.sender, to, s.country, r.country);
    }

    function acknowledgeCustody(uint256 caseId) external {
        Officer storage u = _activeOfficer(msg.sender);
        Case storage c = _getCase(caseId);
        _checkAccess(c, msg.sender, u.country);
        if (c.localOwners[u.country] != msg.sender) revert NotOwner();
        _log(c, Action.CustodyAcknowledged, msg.sender, msg.sender, u.country, u.country);
    }

    /// @notice Recovery: when the current owner in the SPOC's country has been revoked
    ///         (e.g. lost or compromised key), the SPOC reassigns custody to an active officer.
    function recoverCustody(uint256 caseId, address newOwner) external {
        Officer storage s = _activeOfficer(msg.sender);
        if (s.role != Role.SPOC) revert WrongRole();
        Officer storage r = _activeOfficer(newOwner);
        if (r.country != s.country) revert CountryMismatch();
        Case storage c = _getCase(caseId);
        if (!c.isCountryIncharge[s.country]) revert CountryNotInCharge();

        address previous = c.localOwners[s.country];
        if (officers[previous].active) revert OwnerStillActive();

        if (c.globalOwner == previous) {
            c.globalOwner = newOwner;
        }
        c.localOwners[s.country] = newOwner;
        caseIncharge[newOwner][caseId] = true;

        _log(c, Action.CustodyRecovered, previous, newOwner, s.country, s.country);
    }

    /// @notice Appends a correction (by the owner in the jurisdiction that made the entry)
    ///         or a dispute notice (by any assigned officer of a participating jurisdiction).
    function recordCorrection(
        uint256 caseId,
        CorrectionKind kind,
        TargetType targetType,
        uint256 targetIndex,
        string calldata note
    ) external {
        Officer storage u = _activeOfficer(msg.sender);
        Case storage c = _getCase(caseId);
        _checkAccess(c, msg.sender, u.country);
        _authorizeCorrection(c, u.country, kind, targetType, targetIndex);

        Correction storage cr = c.corrections.push();
        cr.kind = kind;
        cr.targetType = targetType;
        cr.country = u.country;
        cr.time = uint64(block.timestamp);
        cr.author = msg.sender;
        cr.targetIndex = targetIndex;
        cr.note = note;

        _log(
            c,
            kind == CorrectionKind.Correction ? Action.CorrectionRecorded : Action.DisputeRecorded,
            msg.sender,
            address(0),
            u.country,
            u.country
        );
        emit CorrectionRecorded(caseId, kind, targetType, targetIndex, msg.sender);
    }

    /// @dev Checks that the target exists and, for a correction, that the caller owns the case
    ///      in the jurisdiction that made the entry.
    function _authorizeCorrection(
        Case storage c,
        bytes2 country,
        CorrectionKind kind,
        TargetType targetType,
        uint256 targetIndex
    ) internal view {
        bytes2 entryCountry;
        if (targetType == TargetType.HistoryEntry) {
            if (targetIndex >= c.history.length) revert InvalidTarget();
            entryCountry = c.history[targetIndex].fromCountry;
        } else {
            if (targetIndex == 0 || targetIndex > c.evs.length) revert InvalidTarget();
            if (!c.isPermitted[targetIndex][country]) revert EvidenceNotPermitted();
            entryCountry = officers[c.evs[targetIndex - 1].createdBy].country;
        }
        if (kind == CorrectionKind.Correction) {
            if (entryCountry != country) revert NotEntryJurisdiction();
            if (!_isOwner(c, msg.sender, country)) revert NotOwner();
        }
    }

    /// @notice Returns all corrections and dispute notices of a case to any assigned participant.
    function getCorrections(uint256 caseId) external view returns (Correction[] memory) {
        Officer storage u = _activeOfficer(msg.sender);
        Case storage c = _getCase(caseId);
        _checkAccess(c, msg.sender, u.country);
        return c.corrections;
    }

    // =====================================================================
    // Algorithm 5: caseQuery (details) - LEO / First Responder
    // =====================================================================
    function getCaseDetails(uint256 caseId) external view returns (CaseView memory v) {
        Officer storage u = _activeOfficer(msg.sender);
        if (u.role != Role.LawEnforcementOfficer && u.role != Role.FirstResponder) revert WrongRole();
        Case storage c = _getCase(caseId);
        _checkAccess(c, msg.sender, u.country);

        v.globalOwner = c.globalOwner;
        v.ctime = c.ctime;
        v.countries = c.countryIncharge;
        v.localOwners = new address[](c.countryIncharge.length);
        for (uint256 i = 0; i < c.countryIncharge.length; i++) {
            v.localOwners[i] = c.localOwners[c.countryIncharge[i]];
        }

        uint256 n;
        for (uint256 i = 0; i < c.evs.length; i++) {
            if (c.isPermitted[i + 1][u.country]) n++;
        }
        v.evidence = new EvidenceView[](n);
        uint256 k;
        for (uint256 i = 0; i < c.evs.length; i++) {
            if (c.isPermitted[i + 1][u.country]) v.evidence[k++] = _evidenceView(c, i);
        }
        v.history = c.history;
    }

    // =====================================================================
    // Algorithm 6: caseQuery (metadata) - SPOC
    // =====================================================================
    function getCaseMetadata(uint256 caseId)
        external
        view
        returns (address globalOwner, uint64 ctime, HistoryEntry[] memory history)
    {
        Officer storage u = _activeOfficer(msg.sender);
        if (u.role != Role.SPOC) revert WrongRole();
        Case storage c = _getCase(caseId);
        _checkAccess(c, msg.sender, u.country);
        return (c.globalOwner, c.ctime, c.history);
    }

    // =====================================================================
    // Algorithm 7: evidenceVerification
    // =====================================================================
    function evidenceVerification(uint256 caseId, uint256 evidenceId, bytes32 computedHash)
        external
        returns (bool ok)
    {
        Officer storage u = _activeOfficer(msg.sender);
        if (u.role != Role.LawEnforcementOfficer && u.role != Role.FirstResponder) revert WrongRole();
        Case storage c = _getCase(caseId);
        _checkAccess(c, msg.sender, u.country);
        if (evidenceId == 0 || evidenceId > c.evs.length) revert EvidenceNotFound();
        if (!c.isPermitted[evidenceId][u.country]) revert EvidenceNotPermitted();

        ok = (c.evs[evidenceId - 1].hash == computedHash);
        _log(
            c,
            ok ? Action.EvidenceVerified : Action.VerificationFailed,
            msg.sender,
            address(0),
            u.country,
            u.country
        );
        emit EvidenceVerified(caseId, evidenceId, msg.sender, ok);
    }

    // =====================================================================
    // Internal helpers
    // =====================================================================
    function _activeOfficer(address a) internal view returns (Officer storage o) {
        o = officers[a];
        if (!o.active) revert NotActiveOfficer();
    }

    function _getCase(uint256 caseId) internal view returns (Case storage c) {
        if (caseId == 0 || caseId > caseCount) revert CaseNotFound();
        c = cases[caseId];
    }

    function _checkAccess(Case storage c, address user, bytes2 country) internal view {
        if (!c.isCountryIncharge[country]) revert CountryNotInCharge();
        if (!caseIncharge[user][c.id]) revert NotAssigned();
    }

    function _isOwner(Case storage c, address user, bytes2 country) internal view returns (bool) {
        return c.globalOwner == user || c.localOwners[country] == user;
    }

    function _addEvidence(Case storage c, EvidenceInput[] calldata items, bytes2 country) internal {
        for (uint256 i = 0; i < items.length; i++) {
            Evidence storage e = c.evs.push();
            uint32 eid = uint32(c.evs.length);
            e.id = eid;
            e.createdTime = uint64(block.timestamp);
            e.createdBy = msg.sender;
            e.hash = items[i].hash;
            e.name = items[i].name;
            e.evidenceType = items[i].evidenceType;
            e.hashAlgorithm = items[i].hashAlgorithm;
            e.storagePointer = items[i].storagePointer;
            c.isPermitted[eid][country] = true;
            emit EvidenceAdded(c.id, eid, items[i].hash, msg.sender);
        }
    }

    /// @dev Rebuilds an evidence item for output, including the list of permitted countries.
    function _evidenceView(Case storage c, uint256 idx) internal view returns (EvidenceView memory v) {
        Evidence storage e = c.evs[idx];
        v.id = e.id;
        v.name = e.name;
        v.createdBy = e.createdBy;
        v.createdTime = e.createdTime;
        v.evidenceType = e.evidenceType;
        v.hash = e.hash;
        v.hashAlgorithm = e.hashAlgorithm;
        v.storagePointer = e.storagePointer;

        uint256 len = c.countryIncharge.length;
        uint256 m;
        for (uint256 j = 0; j < len; j++) {
            if (c.isPermitted[e.id][c.countryIncharge[j]]) m++;
        }
        v.permittedCountries = new bytes2[](m);
        uint256 k;
        for (uint256 j = 0; j < len; j++) {
            bytes2 cc = c.countryIncharge[j];
            if (c.isPermitted[e.id][cc]) v.permittedCountries[k++] = cc;
        }
    }

    function _log(Case storage c, Action action, address from, address to, bytes2 fc, bytes2 tc) internal {
        c.history.push(HistoryEntry(action, uint64(block.timestamp), from, to, fc, tc));
        emit CustodyEvent(c.id, action, from, to, fc, tc);
    }
}

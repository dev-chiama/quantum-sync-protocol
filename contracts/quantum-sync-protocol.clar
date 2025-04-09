;; QuantumSync Protocol - Stacks smart contract that operates as a necesssary Secure Data Transmission System

;; Channel data structure
(define-map ChannelRegistry
  { channel-id: uint }
  {
    initiator: principal,
    target: principal,
    packet-id: uint,
    quantity: uint,
    channel-status: (string-ascii 10),
    genesis-block: uint,
    terminus-block: uint
  }
)

;; Tracking the most recent channel ID
(define-data-var latest-channel-id uint u0)


;; Core constants
(define-constant PROTOCOL_SUPERVISOR tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_NO_CHANNEL (err u101))
(define-constant ERR_ALREADY_PROCESSED (err u102))
(define-constant ERR_TRANSMISSION_FAILED (err u103))
(define-constant ERR_INVALID_CHANNEL_ID (err u104))
(define-constant ERR_INVALID_QUANTITY (err u105))
(define-constant ERR_INVALID_INITIATOR (err u106))
(define-constant ERR_CHANNEL_OUTDATED (err u107))
(define-constant CHANNEL_LIFESPAN_BLOCKS u1008)

;; Helper functions

(define-private (valid-channel-id? (channel-id uint))
  (<= channel-id (var-get latest-channel-id))
)


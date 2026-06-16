-- src/nft_marks.moon
-- Namespace centralisé des marks nft/NFQUEUE réservées par Custos.

-- Bits déjà utilisés ailleurs :
--   0x00000fff : VLAN id transporté dans meta mark.
--   0x00004000+ : marks de règles compilées par filter.nft_compiler.
--   0x00010000 : auth mark interne au compilateur nft.
-- On réserve un bit haut pour demander un rejet réseau forgé par worker_reject.
REJECT_MARK = 0x02000000
REJECT_MARK_HEX = string.format "0x%08x", REJECT_MARK

{ :REJECT_MARK, :REJECT_MARK_HEX }

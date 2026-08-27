meta:
  id: egg_pds_disk # special ProjectEGG format for diskettes, similar to d88
  file-extension: bin
  endian: le

seq:
  - id: magic
    type: str
    encoding: ascii
    size: 4
  - id: disk_type # 0 - 84, 1 or 2 - 168 tracks
    type: u1
  - id: track
    type: track
    repeat: until
    repeat-until: _.num_of_sectors == 0


  
types:
  track:
    seq:
      - id: num_of_sectors
        type: u1
      - id: sectors
        type: sector
        repeat: expr
        repeat-expr: num_of_sectors
  sector:
    seq:
      - id: sheader
        type: sector_head
      - id: sector_data
        size: sheader.size_factor << 7 # like in the code

  sector_head:
    seq:
      - id: cylinder_id
        type: u1
      - id: head_id
        type: u1
      - id: sector_num
        type: u1
      - id: n_code
        type: u1
      - id: status
        if: status != 64
        type: u1
      - id: size_factor
        type: u1
    

# frozen_string_literal: true

require "base64"
require "zstd-ruby"

module DeadlockCodec
  ZSTD_MAGIC = [ 0x28, 0xB5, 0x2F, 0xFD ].freeze
  MAX_NESTING = 64
  MAX_DECOMPRESSED_BYTES = 1_000_000
  SIGNED64_MAX = (1 << 63) - 1
  UNSIGNED64_MOD = 1 << 64

  module_function

  def decode(code)
    raw = Base64.strict_decode64(code.to_s.gsub(/\s/, ""))
    bytes = zstd_frame?(raw) ? Zstd.decompress(raw) : raw
    raise "decompressed payload too large" if bytes.bytesize > MAX_DECOMPRESSED_BYTES
    build_hash(parse_message(bytes))
  end

  def encode(json)
    Base64.strict_encode64(Zstd.compress(encode_top(json)))
  end

  def zstd_frame?(raw)
    raw.byteslice(0, 4) == ZSTD_MAGIC.pack("C*")
  end

  def parse_message(bytes, depth = 0)
    raise "message too deeply nested" if depth > MAX_NESTING
    out = []
    i = 0
    len = bytes.bytesize
    while i < len
      tag, i = read_varint(bytes, i)
      field = tag >> 3
      wire = tag & 7
      case wire
      when 0
        value, i = read_varint(bytes, i)
        out << [ field, wire, to_signed64(value) ]
      when 2
        length, i = read_varint(bytes, i)
        break if length.negative? || i + length > len
        sub = bytes.byteslice(i, length)
        i += length
        text = sub.force_encoding("UTF-8")
        text = text.scrub unless text.valid_encoding?
        if printable_string?(text)
          out << [ field, wire, [ :str, text ] ]
        else
          begin
            out << [ field, wire, [ :msg, parse_message(sub, depth + 1) ] ]
          rescue StandardError
            out << [ field, wire, sub ]
          end
        end
      when 5
        break if i + 4 > len
        out << [ field, wire, bytes.byteslice(i, 4).unpack1("e") ]
        i += 4
      else
        break
      end
    end
    out
  end

  def read_varint(bytes, i)
    result = 0
    shift = 0
    count = 0
    len = bytes.bytesize
    while i < len
      byte = bytes.getbyte(i)
      i += 1
      count += 1
      raise "varint too long" if count > 10
      result |= (byte & 0x7F) << shift
      return [ result, i ] if (byte & 0x80).zero?
      shift += 7
    end
    [ result, i ]
  end

  def to_signed64(value)
    value > SIGNED64_MAX ? value - UNSIGNED64_MOD : value
  end

  def printable_string?(text)
    return false if text.empty?
    text.each_byte.none? do |code|
      (code < 0x20 && code != 0x09 && code != 0x0A && code != 0x0D) || code == 0x7F
    end
  end

  def build_hash(top)
    result = {}
    top.each do |field, _wire, value|
      case field
      when 1 then result[:hero_id] = value
      when 2 then result[:version] = value
      when 3 then result[:hero_build_id] = value
      when 4 then result[:author_account_id] = value
      when 5 then result[:name] = value[1] if value[0] == :str
      when 6 then result[:description] = value[1] if value[0] == :str
      when 7 then result[:language] = value
      when 8 then result[:origin_build_id] = value
      when 9 then result[:field_9] = value
      when 10 then parse_details(value, result)
      when 11 then (result[:tags] ||= []) << value
      when 13 then result[:field_13] = value
      end
    end
    result
  end

  def parse_details(value, result)
    return unless value[0] == :msg
    categories = []
    ability_order = nil
    value[1].each do |field, _wire, inner|
      if field == 1 && inner[0] == :msg
        categories << parse_category(inner[1])
      elsif field == 2 && inner[0] == :msg
        ability_order = parse_ability_order(inner[1])
      end
    end
    details = { mod_categories: categories }
    details[:ability_order] = ability_order if ability_order
    result[:details] = details
  end

  def parse_category(fields)
    category = { mods: [] }
    fields.each do |field, _wire, value|
      case field
      when 1 then category[:mods] << parse_mod(value[1]) if value[0] == :msg
      when 2 then category[:name] = value[1] if value[0] == :str
      when 3 then category[:description] = value[1] if value[0] == :str
      when 4 then category[:height] = value
      when 5 then category[:width] = value
      when 6 then category[:optional] = !value.to_i.zero?
      end
    end
    category
  end

  def parse_mod(fields)
    ability_id = nil
    fields.each { |field, _wire, value| ability_id = value if field == 1 }
    ability_id
  end

  def parse_ability_order(fields)
    changes = []
    fields.each do |field, _wire, value|
      next unless field == 1 && value[0] == :msg
      change = {}
      value[1].each do |inner_field, _inner_wire, inner_value|
        case inner_field
        when 1 then change[:ability_id] = inner_value
        when 2 then change[:currency_type] = inner_value
        when 3 then change[:delta] = inner_value
        when 4 then change[:annotation] = inner_value[1] if inner_value[0] == :str
        end
      end
      changes << change
    end
    { currency_changes: changes }
  end

  def encode_top(json)
    top = binary
    top << encode_field(1, 0, encode_varint(json[:hero_id])) if json.key?(:hero_id)
    top << encode_field(2, 0, encode_varint(json[:version])) if json.key?(:version)
    top << encode_field(3, 0, encode_varint(json[:hero_build_id])) if json.key?(:hero_build_id)
    top << encode_field(4, 0, encode_varint(json[:author_account_id])) if json.key?(:author_account_id)
    top << encode_field(5, 2, encode_string(json[:name])) if json.key?(:name)
    top << encode_field(6, 2, encode_string(json[:description])) if json.key?(:description)
    top << encode_field(7, 0, encode_varint(json[:language])) if json.key?(:language)
    top << encode_field(8, 0, encode_varint(json[:origin_build_id])) if json.key?(:origin_build_id)
    top << encode_field(9, 0, encode_varint(json[:field_9])) if json.key?(:field_9)
    top << encode_details(json[:details]) if json[:details]&.[](:mod_categories)
    (json.fetch(:tags) { [] }).each { |tag| top << encode_field(11, 0, encode_varint(tag)) }
    top << encode_field(13, 0, encode_varint(json[:field_13])) if json.key?(:field_13)
    top
  end

  def encode_details(details)
    body = binary
    details.fetch(:mod_categories) { [] }.each do |category|
      category_bytes = binary
      (category.fetch(:mods) { [] }).each do |mod|
        category_bytes << encode_field(1, 2, encode_length_delimited(encode_field(1, 0, encode_varint(mod))))
      end
      category_bytes << encode_field(2, 2, encode_string(category[:name])) if category.key?(:name)
      category_bytes << encode_field(3, 2, encode_string(category[:description])) if category.key?(:description)
      category_bytes << encode_field(4, 5, [ category[:height] ].pack("e")) if category.key?(:height)
      category_bytes << encode_field(5, 5, [ category[:width] ].pack("e")) if category.key?(:width)
      category_bytes << encode_field(6, 0, encode_varint(1)) if category[:optional]
      body << encode_field(1, 2, encode_length_delimited(category_bytes))
    end
    if details.fetch(:ability_order) { {} }[:currency_changes]
      changes = binary
      details[:ability_order][:currency_changes].each do |change|
        change_bytes = binary
        change_bytes << encode_field(1, 0, encode_varint(change[:ability_id])) if change.key?(:ability_id)
        change_bytes << encode_field(2, 0, encode_varint(change[:currency_type])) if change.key?(:currency_type)
        change_bytes << encode_field(3, 0, encode_varint(change[:delta])) if change.key?(:delta)
        change_bytes << encode_field(4, 2, encode_string(change[:annotation])) if change[:annotation]
        changes << encode_field(1, 2, encode_length_delimited(change_bytes))
      end
      body << encode_field(2, 2, encode_length_delimited(changes))
    end
    encode_field(10, 2, encode_length_delimited(body))
  end

  def encode_varint(value)
    number = value.to_i
    number += UNSIGNED64_MOD if number < 0
    bytes = String.new(capacity: 10, encoding: "ASCII-8BIT")
    while number > 0x7F
      bytes << ((number & 0x7F) | 0x80)
      number >>= 7
    end
    bytes << (number & 0x7F)
    bytes
  end

  def encode_field(field, wire, value_bytes)
    value_bytes = value_bytes.b unless value_bytes.is_a?(String) && value_bytes.encoding == Encoding::ASCII_8BIT
    encode_varint((field << 3) | wire) + value_bytes
  end

  def encode_string(value)
    encode_length_delimited(value.to_s.b)
  end

  def encode_length_delimited(bytes)
    bytes = bytes.b unless bytes.is_a?(String) && bytes.encoding == Encoding::ASCII_8BIT
    encode_varint(bytes.bytesize) + bytes
  end

  def binary
    String.new(capacity: 64, encoding: "ASCII-8BIT")
  end
end

defmodule ExAws.CloudFront.CannedPolicy do
  @enforce_keys [:url, :expire_time]

  defstruct [:url, :expire_time]

  @doc """
  Create a Canned Policy.
  """
  def new(url), do: new(url, ExAws.Utils.now_in_seconds + 1800)
  def new(url, %DateTime{} = expire_time), do: new(url, DateTime.to_unix(expire_time))
  def new(url, expire_time) when is_integer(expire_time), do: new(url, expire_time: expire_time)
  def new(url, opts) when is_binary(url) and is_list(opts) do
    %__MODULE__{
      url: url,
      expire_time: Keyword.get(opts, :expire_time)
    }
  end
end

defimpl ExAws.CloudFront.Policy, for: ExAws.CloudFront.CannedPolicy do
  import ExAws.CloudFront.Utils

  @doc """
  Create a Signed URL Using a Canned Policy.
  """
  def get_signed_url(canned_policy, %{keypair_id: keypair_id, private_key: private_key} = config) do
    get_signed_url(canned_policy, config, fn payload ->
      [
        {"Expires", canned_policy.expire_time},
        {"Signature", payload |> create_signature(private_key) |> aws_encode64},
        {"Key-Pair-Id", keypair_id}
      ]
    end)
  end

  @doc """
  Creating a Signature for a Signed Cookie That Uses a Canned Policy.
  """
  def get_signed_cookies(canned_policy, %{keypair_id: keypair_id, private_key: private_key} = config) do
    get_signed_cookies(canned_policy, config, fn payload ->
      %{
        "CloudFront-Expires" => canned_policy.expire_time |> to_string,
        "CloudFront-Signature" => payload |> create_signature(private_key) |> aws_encode64,
        "CloudFront-Key-Pair-Id" => keypair_id
      }
    end)
  end

  @doc """
  Create a Policy Statement for a Signed URL That Uses a Canned Policy.
  """
  def to_statement(%{url: url, expire_time: expire_time}) do
    cond do
      expire_time >= 2147483647 ->
        {:error, "`expire_time` must be less than 2147483647 (January 19, 2038 03:14:08 GMT)"}
      expire_time <= ExAws.Utils.now_in_seconds ->
        {:error, "`expire_time` must be after the current time"}
      :else -> {:ok, %{
        "Statement" => [%{
          "Resource" => url,
          "Condition" => %{
            "DateLessThan" => %{
              "AWS:EpochTime" => expire_time
            }
          }
        }]
      }}
    end
  end
end

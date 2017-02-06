defprotocol ExAws.CloudFront.Policy do
  @doc """
  Create a Signed URL Using a Policy.
  """
  def get_signed_url(policy, config)

  @doc """
  Creating a Signature for a Signed Cookie That Uses a Policy.
  """
  def get_signed_cookies(policy, config)

  @doc """
  Create a Policy Statement for a Signed URL That Uses a Policy.
  """
  def to_statement(policy)
end
